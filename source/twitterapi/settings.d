module twitterapi.settings;

import std.file : exists, readText;
import std.json : JSONValue, parseJSON;

import twitterapi.constants;

struct OAuthSettings {
	private string oauthConsumerKey;
	private string oauthConsumerSecret;
	private string oauthToken;
	private string oauthTokenSecret;
	private string oauthSignatureMethod;
	private string oauthVersion;
	
	@property {
		void consumerKey(string consumerKey) {
			oauthConsumerKey = consumerKey;
		}
		
		string consumerKey() {
			return oauthConsumerKey;
		}
		
		void consumerSecret(string consumerSecret) {
			oauthConsumerSecret = consumerSecret;
		}
		
		string consumerSecret() {
			return oauthConsumerSecret;
		}
		
		void token(string token) {
			oauthToken = token;
		}
		
		string token() {
			return oauthToken;
		}
		
		void tokenSecret(string tokenSecret) {
			oauthTokenSecret = tokenSecret;
		}
		
		string tokenSecret() {
			return oauthTokenSecret;
		}
		
		void signatureMethod(string signatureMethod) {
			oauthSignatureMethod = signatureMethod;
		}
		
		string signatureMethod() {
			return oauthSignatureMethod;
		}
		
		void protocolVersion(string protocolVersion) {
			oauthVersion = protocolVersion;
		}
		
		string protocolVersion() {
			return oauthVersion;
		}
	}
}

private static JSONValue readJsonFileSettings(string file) {
	if (!exists(file)) {
		throw new Exception("file ["~file~"] not found");
	}
	string fileContent;
	try {
		fileContent = readText(file);
	} catch (Exception e) {
		throw new Exception("read file ["~file~"] error", e); 
	}
	try {
		return parseJSON(fileContent);
	} catch (Exception e) {
		throw new Exception("parse json file ["~file~"] error", e);
	}
}
	
public static OAuthSettings fromJson(string file) {
	JSONValue json = readJsonFileSettings(file);
	OAuthSettings settings;
	settings.consumerKey = json.object[OAUTH_CONSUMER_KEY].str;
	settings.consumerSecret = json.object[OAUTH_CONSUMER_SECRET].str;
	settings.token = json.object[OAUTH_TOKEN].str;
	settings.tokenSecret = json.object[OAUTH_TOKEN_SECRET].str;
	settings.signatureMethod = json.object[OAUTH_SIGNATURE_METHOD].str;
	settings.oauthVersion = json.object[OAUTH_VERSION].str;
	return settings;
}
