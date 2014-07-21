twitterapi.d
============

This client supports Twitter's REST and Streaming APIs (version 1.1). Work in progress.

Some Code Examples
============

First, prepare OAuth settings from json file:
```
import twitterapi.settings;
auto settings = fromJson("/path/to/file/settings.json");
```

Next, create a client:
```
auto client = new TwitterClient(ApiType.Stream, settings);
```

create a request:
```
ApiRequest request = ApiRequest(
		"https://api.twitter.com/1.1/search/tweets.json", 
		GET,
		["q":"D language"] 
	);
```
and then run it:
```
client.execute(request, new SimpleProcessor);
```
