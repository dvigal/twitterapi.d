module twitterapi.client;

import std.base64 : Base64;
import std.uri : encodeComponent;
import std.math : abs;
import std.random : uniform;
import std.digest.sha : sha1Of;
import std.file : readText, exists;
import std.json : JSONValue, parseJSON;

import core.atomic;
import core.thread;

import std.net.curl, std.stdio, std.string,
 	   std.functional, std.algorithm, std.datetime, 
 	   std.conv, std.array;
import std.concurrency; 	   
 	   
import etc.c.curl; 	   
 	   
import twitterapi.settings : OAuthSettings, fromJson; 	   
import twitterapi.constants;

public final class TwitterClient {
	private Signer!ApiRequest signer;
	private OAuthSettings settings;
	private ApiType type;
	
	this(OAuthSettings settings) {
		this(ApiType.Rest, settings, new TwitterOAuthSigner(settings));
	}
	
	this(ApiType type, OAuthSettings settings) {
		this(type, settings, new TwitterOAuthSigner(settings));
	}
	
	this(ApiType type, OAuthSettings settings, Signer!ApiRequest signer) {		 
		this.type = type;
		this.signer = new TwitterOAuthSigner(settings);
		this.settings = settings;
		
	}
	
	void execute(ApiRequest request, ResponseProcessor!string processor) {
		if (type == ApiType.Rest) {
			new RestExecutor(signer, request, processor).exec;
		} else {
			new StreamExecutor(signer, request, processor).exec;
		}
	}
} 

interface ResponseProcessor(T) {
	void process(T value);
}

interface Executor {
	void exec();
	
	void stop();		
}

private class RestExecutor : Executor {
	private Signer!ApiRequest signer;
	private ApiRequest request;
	private ResponseProcessor!string processor;
	
	this(Signer!ApiRequest signer, ApiRequest request, ResponseProcessor!string processor) {
		this.signer = signer;
		this.request = request;
		this.processor = processor;
	}
	
	void exec() {
		HTTP http = HTTP();
		signer.sign(request);
		http.addRequestHeader(HEADER_NAME_AUTHORIZATION, request.getHeader);
		if (request.getMethod == GET) {
			auto url = 
			request.getParams !is null && request.getParams.length > 0
			 ? request.getUrl~"?"~request.getParams.keys.map!(k => k~"="~encodeComponent(request.getParams[k])).join("&") 
			 : request.getUrl;
			processor.process(to!string(get(url, http)));
		}
		else {
			processor.process(
				to!string(
					post(request.getUrl, 
						request.getParams !is null && request.getParams.length > 0
						 ? request.getParams.keys.map!(k => k~"="~encodeComponent(request.getParams[k])).join("&")
						 : null, http)
					)
				);
		}
		http.shutdown;
	}
	
	void stop() {
	}
	
}

private class StreamExecutor : Executor {
	private Signer!ApiRequest signer;
	private ApiRequest request;
	private ResponseProcessor!string processor;
	private shared bool isStoped;
	
	this(Signer!ApiRequest signer, ApiRequest request, ResponseProcessor!string processor) {
		this.signer = signer;
		this.request = request;
		this.processor = processor;
	}
	
	void exec() {
		void exec()
		{
			HTTP http = HTTP();
			auto url = request.getParams !is null && request.getParams.length > 0 
				? request.getParams.keys.map!(k => k~"="~encodeComponent(request.getParams[k])).join("&")
				: request.getUrl;
			http.url = url;
			signer.sign(request);
			http.addRequestHeader(HEADER_NAME_AUTHORIZATION, request.getHeader);
			if (request.getMethod == GET) {
				
				http.method = HTTP.Method.get;
			} else {
				http.method = HTTP.Method.post;
			}
			http.onReceive = (ubyte[] data) {
				processor.process(to!(string)(data));
				return data.length;
			};
			bool ok = true;
			http.onReceiveStatusLine = (HTTP.StatusLine status) {
				writeln("Got status line " ~ status.toString);
				if (status.code != 0) {
					ok = false;
				}
			};
			while (ok && !cas(&isStoped, true, false)) {
				http.perform;
			}
			http.shutdown;
		}
		new Thread(&exec).start;
	}
	
	void stop() {
		atomicStore(isStoped, true);
	}
	
}

public enum ApiType {
	Rest,
	Stream
}

struct HttpMethod {
	private string name;
	
	private this(string name) {
		this.name = name;
	}
}
public enum 
	GET = HttpMethod("GET"),
	POST = HttpMethod("POST");
	
public struct ApiRequest {
	private string[string] header;
	private string url;
	private HttpMethod method;
	private immutable(string[string]) params;
	
	this(string url, HttpMethod method, immutable(string[string]) params = null) {
		assert (method == GET || method == POST, "unknown http method");
		this.header = ["":""];
		this.url = url;
		this.method = method;
		this.params = params;
	}
	
	package auto getHeader() {
		return this.header[HEADER_NAME_AUTHORIZATION];
	}
	
	package void setHeader(string header) {
		this.header[HEADER_NAME_AUTHORIZATION] = header;
	}
	
	package string getUrl() {
		return url;
	}
	
	package HttpMethod getMethod() {
		return method;
	}
	
	package immutable(string[string]) getParams() {
		return params; 
	}
}

interface Signer(T) {
	public void sign(T value);
	
	final ubyte[] hmac_sha1(in string key, in string message) {
		  auto padding(in ubyte[] k){
		    auto h = (64 < k.length)? sha1Of(k): k;
		    return h ~ new ubyte[64 - h.length];
		  }
		  const k = padding(cast(ubyte[])key);
		  return sha1Of((k.map!q{cast(ubyte)(a^0x5c)}.array) ~ sha1Of((k.map!q{cast(ubyte)(a^0x36)}.array) ~ cast(ubyte[])message)).dup;
	}
}

class TwitterOAuthSigner : Signer!(ApiRequest) {
	private OAuthSettings oauthsettings;
	
	this(OAuthSettings settings) {
		this.oauthsettings = settings;
	}
	
	private string collect(ApiRequest request, string[string] oauthparams) {
		string[string] encoded;
		foreach(key, value; oauthparams) {
			encoded[encodeComponent(key)] = encodeComponent(value); 
		}
		foreach(key, value; request.getParams) {
			encoded[encodeComponent(key)] = encodeComponent(value);
		}
		return encoded.keys.sort.map!(k => k~"="~encoded[k]).join("&");
	}
	
	public void sign(ApiRequest request) {
		string[string] oauthparams;
		oauthparams[OAUTH_CONSUMER_KEY] = oauthsettings.consumerKey;
		oauthparams[OAUTH_NONCE] = generateNonce(); 
		oauthparams[OAUTH_SIGNATURE_METHOD] = oauthsettings.signatureMethod;
		oauthparams[OAUTH_TIMESTAMP] = generateTimestamp();
		oauthparams[OAUTH_TOKEN] = oauthsettings.token;
		oauthparams[OAUTH_VERSION] = oauthsettings.protocolVersion;
		
		string[string] params;
		foreach(key, value; request.getParams) {
			params[key] = value;
		}
		foreach(key, value; oauthparams) {
			params[key] = value;
		}
		 
		string sigBaseString = [
			std.string.toUpper(request.getMethod.name),
			encodeComponent(request.getUrl),
			encodeComponent(collect(request, oauthparams))
		].join("&");
		
		oauthparams[OAUTH_SIGNATURE] = "";
		
		debug(TWITTER_CLIENT_DEBUG)
			writeln("SIGNED BASE STRING => " ~ sigBaseString);
		
		string signingKey = 
			encodeComponent(
				oauthsettings.consumerSecret) ~ "&" ~
			encodeComponent(
				oauthsettings.tokenSecret
			);
		debug(TWITTER_CLIENT_DEBUG)
			writeln("SIGNING KEY => " ~ signingKey);
			
			
		string signature = Base64.encode(hmac_sha1(signingKey, sigBaseString));
		debug(TWITTER_CLIENT_DEBUG)
			writeln("SIGNATURE => " ~ signature);

		oauthparams[OAUTH_SIGNATURE] = signature;
		string header = "OAuth " ~ oauthparams.keys.map!(k => encodeComponent(k)~"="~'"'~encodeComponent(oauthparams[k])~'"').join(", ");
		debug(TWITTER_CLIENT_DEBUG)
			writeln("AUTHORIZATION HEADER => " ~ header);	
			
		request.setHeader(header);
	}
	
	private string generateNonce() {
		return Base64.encode(cast(ubyte[])to!string(abs(uniform!long()) + Clock.currTime.toUnixTime));
	}
	
	private string generateTimestamp() {
		return Clock.currTime.toUnixTime.to!string;
	}
	
}

class SimpleProcessor : ResponseProcessor!string {
	void process(string data) {
		writeln("Got data: " ~ data);
	}
}

void main() {
	
    auto settings = fromJson("./settings.json");
    auto twitter = new TwitterClient(ApiType.Stream, settings);

    ApiRequest request = ApiRequest(
		"https://stream.twitter.com/1.1/statuses/sample.json", 
		GET 
	);

    twitter.execute(request, new SimpleProcessor);
}