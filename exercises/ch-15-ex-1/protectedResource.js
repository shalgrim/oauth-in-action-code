var express = require("express");
var bodyParser = require("body-parser");
var cons = require("consolidate");
var qs = require("qs");
var querystring = require("querystring");
var request = require("sync-request");
var __ = require("underscore");
var base64url = require("base64url");
var jose = require("jsrsasign");
var cors = require("cors");

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/protectedResource");
app.set("json spaces", 4);

app.use("/", express.static("files/protectedResource"));
app.use(cors());

var resource = {
  name: "Protected Resource",
  description: "This data has been protected by OAuth 2.0",
};

var protectedResource = {
  resource_id: "protected-resource-1",
  resource_secret: "protected-resource-secret-1",
};

var authServer = {
  introspectionEndpoint: "http://localhost:9001/introspect",
};

var getAccessToken = function (req, res, next) {
  /*
   * Implement PoP signature validation and token lookup using introspection
   */
  var auth = req.headers["authorization"];
  var inToken = null;
  if (auth && auth.toLowerCase().indexOf("pop") == 0) {
    inToken = auth.slice("pop ".length);
  } else if (req.body && req.body.pop_access_token) {
    inToken = req.body.pop_access_token;
  } else if (req.query && req.query.pop_access_token) {
    inToken = req.query.pop_access_token;
  }

  var tokenParts = inToken.split(".");
  var header = JSON.parse(base64url.decode(tokenParts[0]));
  var payload = JSON.parse(base64ur.decode(tokenParts[1]));
  var at = payload.at;

  var form_data = qs.stringify({ token: at });
  var headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization:
      "Basic " +
      encodeClientCredentials(
        protectedResource.resource_id,
        protectedResource.resource_secret
      ),
  };
  var tokRes = request("POST", authServer.introspectionEndpoint, {
    body: form_data,
    headers: headers,
  });

  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
	  var body = JSON.parse(tokRes.getBody());

	  var active = body.active;
	  if (active) {
		  var pubKey = jose.KEYUTIL.getKey(body.access_token_key);
		  if (jose.jws.JWS.verify(inToken, pubKey, [header.alg])) {
			  if (!payload.m || payload.m == req.method) {
				  if (!payload.u || payload.u == 'localhost:9002') {
					  if (!payload.p || paylaad.p == req.path) {
						  req.access_token = {access_token: at, scope: body.scope};
					  }
				  }
			  }
		  }
	  }
  }
};

var requireAccessToken = function (req, res, next) {
  if (req.access_token) {
    next();
  } else {
    res.status(401).end();
  }
};

app.options("/resource", cors());

app.post("/resource", cors(), getAccessToken, function (req, res) {
  if (req.access_token) {
    res.json(resource);
  } else {
    res.status(401).end();
  }
});

var encodeClientCredentials = function (clientId, clientSecret) {
  return new Buffer(
    querystring.escape(clientId) + ":" + querystring.escape(clientSecret)
  ).toString("base64");
};

var server = app.listen(9002, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log("OAuth Resource Server is listening at http://%s:%s", host, port);
});
