module twitter;

import std.base64,
 	   std.net.curl, 
 	   std.stdio, 
 	   std.json,
 	   std.file,
 	   std.string,
 	   std.uri, 
 	   std.functional, 
 	   std.digest.sha, 
 	   std.algorithm, 
 	   std.datetime, 
 	   std.conv,
 	   std.array,
 	   core.time;


class TwitterClient {
	private Signer!ApiRequest signer;
	private TwitterOAuthSettings settings;
	private TwitterApiType type;
	
	this(TwitterApiType type, TwitterOAuthSettings settings) {
		this.type = type;
		this.signer = new TwitterOAuthSigner(settings);
		this.settings = settings;
	}
	
	Connection execute(ApiRequest request, ResponseProcessor!string processor) {
		signer.sign(request);
		auto connection = new RestConnection(request, processor);
		connection.connect;
		return connection;
	}
	
} 

interface ResponseProcessor(T) {
	void process(T value);
}

interface Connection {
	
	void connect();
	
	void release();
	
	
}

class RestConnection : Connection {
	private HTTP http;
	private ApiRequest request;
	private ResponseProcessor!string processor;
	
	this(ApiRequest request, ResponseProcessor!string processor) {
		http = HTTP();
		this.request = request;
		this.processor = processor;
	}
	
	void connect() {
		http.addRequestHeader("Authorization", request.getHeader);
		auto params = request.getParams.keys.map!(k => k~"="~encodeComponent(request.getParams[k])).join("&");
		processor.process(to!string(get(request.getUrl~"?"~params, http)));
	}
	
	void release() {
		http.shutdown;
	}
	
}

//class StreamConnection : Connection {
//	
//	
//	
//	void release() {
//		
//	}
//}

enum TwitterApiType {
	Rest,
	Stream
}

private static JSONValue readJsonFileSettings(string file) {
	if (!std.file.exists(file)) {
		throw new Exception("file ["~file~"] not found");
	}
	string fileContent;
	try {
		fileContent = std.file.readText(file);
	} catch (Exception e) {
		throw new Exception("read file ["~file~"] error", e); 
	}
	try {
		return std.json.parseJSON(fileContent);
	} catch (Exception e) {
		throw new Exception("parse json file ["~file~"] error", e);
	}
}
	
private static TwitterOAuthSettings fromJson(JSONValue value) {
	debug(TWITTER_CLIENT_DEBUG) 
		writeln("fromJson(JSONValue value) => "~value.toString);
		
	string[string] settings = [
		"oauth_consumer_key"           : value.object["oauth_consumer_key"].str,
		"oauth_consumer_secret"        : value.object["oauth_consumer_secret"].str,
		"oauth_token"	         : value.object["oauth_token"].str,
		"oauth_token_secret" 	 : value.object["oauth_token_secret"].str,
		"oauth_signature_method" : value.object["oauth_signature_method"].str,
		"oauth_version" 		 : value.object["oauth_version"].str
	];
	debug(TWITTER_CLIENT_DEBUG) 
		foreach(key, value; settings) {
			writeln("TwitterOAuthSettings => key{"~key~"}:value{"~value~"}");
		}
	return TwitterOAuthSettings(settings);
}


struct ApiRequest {
	private string[string] header;
	private string url;
	private string endpoint;
	private immutable(string) method;
	private immutable(string[string]) params;
	
	this(string url, immutable(string) method, immutable(string[string]) params = ["":""]) {
		this.header = ["":""];
		this.url = url;
		this.method = method;
		this.params = params;
	}
	
	package auto getHeader() {
		return this.header["Authorization"];
	}
	
	package void setHeader(string header) {
		this.header["Authorization"] = header;
	}
	
	package string getUrl() {
		return url;
	}
	
	package string getMethod() {
		return method;
	}
	
	package immutable(string[string]) getParams() {
		return params; 
	}
}

interface Signer(T) {
	public void sign(T str);
	
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
	private TwitterOAuthSettings oauthsettings;
	
	this(TwitterOAuthSettings settings) {
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
		oauthparams["oauth_consumer_key"] = oauthsettings.settings["oauth_consumer_key"];
		oauthparams["oauth_nonce"] = "57aae85a0b72343d1333b6484a80b8f7"; 
		oauthparams["oauth_signature_method"] = oauthsettings.settings["oauth_signature_method"];
		oauthparams["oauth_timestamp"] = Clock.currTime.toUnixTime.to!string;
		oauthparams["oauth_token"] = oauthsettings.settings["oauth_token"];
		oauthparams["oauth_version"] = oauthsettings.settings["oauth_version"];
		
		string[string] params;
		foreach(key, value; request.getParams) {
			params[key] = value;
		}
		foreach(key, value; oauthparams) {
			params[key] = value;
		}
		 
		string sigBaseString = [
			std.string.toUpper(request.getMethod),
			encodeComponent(request.getUrl),
			encodeComponent(collect(request, oauthparams))
		].join("&");
		
		oauthparams["oauth_signature"] = "";
		
		debug(TWITTER_CLIENT_DEBUG)
			writeln("SIGNED BASE STRING => " ~ sigBaseString);
		
		string signingKey = 
			encodeComponent(
				oauthsettings.settings["oauth_consumer_secret"]) ~ "&" ~
			encodeComponent(
				oauthsettings.settings["oauth_token_secret"]
			);
		debug(TWITTER_CLIENT_DEBUG)
			writeln("SIGNING KEY => " ~ signingKey);
			
			
		string signature = Base64.encode(hmac_sha1(signingKey, sigBaseString));
		debug(TWITTER_CLIENT_DEBUG)
			writeln("SIGNATURE => " ~ signature);

		oauthparams["oauth_signature"] = signature;
		string header = "OAuth " ~ oauthparams.keys.map!(k => encodeComponent(k)~"="~'"'~encodeComponent(oauthparams[k])~'"').join(", ");
		debug(TWITTER_CLIENT_DEBUG)
			writeln("AUTHORIZATION HEADER => " ~ header);	
			
		request.setHeader(header);
	}
	
}


struct TwitterOAuthSettings {
	private string[string] settings;
	
	this(string[string] settings) {
		this.settings = settings;
	}
	
}

class SimpleProcessor : ResponseProcessor!string {
	void process(string data) {
		writeln("Got data: " ~ data);
	}
}

void main() {
	
	auto settings = fromJson(readJsonFileSettings("./settings.json"));
	
	ApiRequest request = ApiRequest(
		"https://api.twitter.com/1.1/search/tweets.json", 
		"get", 
		["q" : "haskell"]
	);
    
    auto twitter = new TwitterClient(TwitterApiType.Rest, settings);
    
    twitter.execute(request, new SimpleProcessor);
	
}