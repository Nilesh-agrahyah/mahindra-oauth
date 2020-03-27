var url = require("url");
var flash = require("connect-flash");
var morgan = require("morgan");
var express = require("express");
var passport = require("passport");
var mongoose = require("mongoose");
var bodyParser = require("body-parser");
var BasicStrategy = require("passport-http").BasicStrategy;
var LocalStrategy = require("passport-local").Strategy;
var PassportOAuthBearer = require("passport-http-bearer");
var morgan = require("morgan");
var cookieSession = require("cookie-session");
const request = require("request");
var oauthServer = require("./oauth");
const account = require("./models/account");

var port = process.env.VCAP_APP_PORT || process.env.PORT || 3000;
var host = process.env.VCAP_APP_HOST || "0.0.0.0";
var mongo_url = process.env.MONGO_URL || "mongodb://localhost/MahindraUserDB";

mongoose.Promise = global.Promise;
var mongoose_options = {
  auto_reconnect: true,
  useNewUrlParser: true,
  useUnifiedTopology: true
};
var mongoose_connection = mongoose.connection;

mongoose_connection.on("connecting", function() {
  console.log(`***connecting to MongoDB URL -> ${mongo_url}***`);
});

mongoose_connection.on("error", function(error) {
  console.error("Error in MongoDb connection: " + error);
  //mongoose.disconnect();
});

mongoose_connection.on("connected", function() {
  console.log("***MongoDB connected!***");
});

mongoose_connection.once("open", function() {
  console.log("***MongoDB connection opened!***");
});

mongoose_connection.on("reconnected", function() {
  console.log("***MongoDB reconnected!***");
});

mongoose_connection.on("disconnected", function() {
  console.log("MongoDB disconnected!");
});

mongoose.connect(mongo_url, mongoose_options);

mongoose.set("useFindAndModify", false);
mongoose.set("useCreateIndex", true);

var Account = require("./models/account");
var oauthModels = require("./models/oauth");
var app_id = "https://mahindra-oauth.herokuapp.com"; //Change according to host used

var app = express();

app.set("view engine", "ejs");
app.enable("trust proxy");
app.use(express.static("public"));
app.use(morgan("tiny"));
app.use(
  cookieSession({
    keys: ["secret1", "secret2"]
  })
);
app.use(flash());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

function requireHTTPS(req, res, next) {
  if (req.get("X-Forwarded-Proto") === "http") {
    //FYI this should work for local development as well
    var url = "http://" + req.get("host");
    if (req.get("host") === "localhost") {
      url += ":" + port;
    }
    url += req.url;
    return res.redirect(url);
  }
  next();
}

app.use(requireHTTPS);

app.use("/", express.static("static"));

passport.use(new LocalStrategy(Account.authenticate()));

passport.use(new BasicStrategy(Account.authenticate()));

passport.serializeUser(Account.serializeUser());
passport.deserializeUser(Account.deserializeUser());

var accessTokenStrategy = new PassportOAuthBearer(function(token, done) {
  console.log("accessTokenStrategy: %s", token);
  oauthModels.AccessToken.findOne({ token: token })
    .populate("user")
    .populate("grant")
    .exec(function(error, token) {
      /* 		console.log("db token: %j", token);
					console.log("db token.active: " + token.active);
					console.log("db token.grant : " + token.grant.active);
					console.log("db token.user: " + token.user); */
      if (token && token.active && token.grant.active && token.user) {
        // console.log("Token is GOOD!");
        console.log("db token: %j", token);
        console.log("db token.active: " + token.active);
        console.log("db token.grant : " + token.grant.active);
        console.log("db token.user: " + token.user);
        done(null, token.user, { scope: token.scope });
      } else if (!error) {
        console.log("TOKEN PROBLEM");
        done(null, false);
      } else {
        console.log("TOKEN PROBLEM 2");
        console.log(error);
        done(error);
      }
    });
});

passport.use(accessTokenStrategy);

/* function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/login");
  }
} */

app.get("/mahindra/register", function(req, res) {
  data.clientId = req.query.client_id;
  data.scope = req.query.scope;
  data.responseType = req.query.response_type;
  data.redirectURI = req.query.redirect_uri;
  data.state = req.query.state;
  // data.number = req.body.phNo;
  res.render("pages/index", {
    user: req.user,
    home: true,
    clientId: req.query.client_id,
    responseType: req.query.response_type,
    redirectURI: req.query.redirect_uri,
    scope: req.query.scope,
    state: req.query.state
  });
  console.log(
    `***Register pages query params: ${JSON.stringify({
      clientId: req.query.client_id,
      responseType: req.query.response_type,
      redirectURI: req.query.redirect_uri,
      scope: req.query.scope,
      state: req.query.state
    })} ***`
  );
});

app.get("/login", function(req, res) {
  res.render("pages/login", { user: req.user, message: req.flash("error") });
});

app.get("/logout", function(req, res) {
  req.logout();
  if (req.query.next) {
    res.redirect(req.query.next);
  } else {
    res.redirect("/");
  }
});

//app.post('/login',passport.authenticate('local', { failureRedirect: '/login', successRedirect: '/2faCheck', failureFlash: true }));
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true
  }),
  function(req, res) {
    //console.log("value of req in  /login" + req)
    console.log("value of req.query.next in " + req.query.next);

    if (req.query.next) {
      res.redirect(req.query.next);
    } else {
      res.send(`${app_id}/auth/start`); //Change according to host used
    }
  }
);

app.get("/newuser", function(req, res) {
  res.render("pages/register", { user: req.user });
});

app.post("/newuser", async function(req, res) {

  Account.register(
    new Account({
      username: req.body.username,
      email: req.body.email,
      mqttPass: "foo",
      fullname: req.body.fullname
    }),
    req.body.password,
    function(err, account) {
      if (err) {
        console.log(err);
        return res.status(400).send(err.message);
      }

      passport.authenticate("local")(req, res, function() {
        console.log("created new user %s", req.body.username);
        res.status(201).send("New user added");
      });
    }
  );
});

class bufferData {
  constructor(
    custId,
    number,
    clientId,
    state,
    scope,
    responseType,
    redirectURI,
    response
  ) {
    this.custId = custId;
    this.number = number;
    this.clientId = clientId;
    this.state = state;
    this.scope = scope;
    this.responseType = responseType;
    this.redirectURI = redirectURI;
    this.response = response
  }
}

let data = new bufferData(
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined,
  undefined
);

app.post("/mahindra/newuser", async (req, res) => {
  data.clientId = req.body.clientId;
  data.scope = req.body.scope;
  data.responseType = req.body.responseType;
  data.redirectURI = req.body.redirectURI;
  data.state = req.body.state;
  data.number = req.body.phNo;
  console.log(
    `***Data stored in Buffer class: ${{
      clientId: data.clientId,
      responseType: data.responseType,
      redirectURI: data.redirectURI,
      scope: data.scope,
      state: data.state,
      phNo: data.number
    }} ***`
  );

  
  let checkNoExists = await Account.findOne({username: req.body.phNo});

  console.log(`***value of check is no already exists: ${checkNoExists}***`);
  if(checkNoExists == null){
    var options = {
      method: "POST",
      url: `${app_id}/newuser`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      form: {
        'username': req.body.phNo,
        'fullname': req.body.name,
        'email': req.body.email,
        'password': "mahindratest@123"
      }
    };
    request(options, function(error, response) {
      if (error) {
        return res.send({ status: 403 });
      }
      console.log(options);
      console.log("Response from POST 'newuser': ", response.body);
    });
  }else{
    checkNoExists.email = req.body.email;
    checkNoExists.fullname = req.body.name;
    await checkNoExists.save();
    // console.log("User details updated: ",userUpdate)
  }
  res.redirect(
    `${app_id}/auth/start?scope=${data.scope}&client_id=${data.clientId}&redirect_uri=${data.redirectURI}&response_type=${data.responseType}&CustNo=${data.number}&state=${data.state}`
  );

});

// app.post("/mahindra/ls", (req, res) => {
//   var options = {
//     method: "POST",
//     url: `${app_id}/newuser`,
//     headers: {
//       "Content-Type": "application/x-www-form-urlencoded"
//     },
//     form: {
//       username: req.query.CustNo,
//       password: "mahindra@123"
//     }
//   };

//   request(options, function(error, response) {
//     if (error) {
//       return res.send({ status: 403 });
//     }
//     console.log(options);
//     console.log("Response from POST 'newuser': ", response.body);
//     res.redirect(
//       `${app_id}/auth/start?scope=${data.scope}&client_id=${data.clientId}&redirect_uri=${data.redirectURI}&response_type=${data.responseType}&CustNo=${req.body.phNo}&state=${data.state}`
//     );
//   });
// });

app.get(
  "/auth/start",
  oauthServer.authorize(function(applicationID, redirectURI, done) {
    console.log("applicationID " + applicationID);
    oauthModels.Application.findOne({ oauth_id: applicationID }, async function(
      error,
      application
    ) {
      if (application) {
        var match = false,
          uri = url.parse(redirectURI || "");
        for (var i = 0; i < application.domains.length; i++) {
          console.log("%s - %s - %j", application.domains[i], redirectURI, uri);
          if (
            uri.host == application.domains[i] ||
            uri.protocol == application.domains[i]
          ) {
            match = true;
            break;
          }
        }
        if (match && redirectURI && redirectURI.length > 0) {
          // let user = await account.findOne({ email: data.custEmail });
          done(null, application, redirectURI);
        } else {
          done(
            new Error(
              "You must supply a redirect_uri that is a domain or url scheme owned by your app."
            ),
            false
          );
        }
      } else if (!error) {
        done(
          new Error(
            "There is no app with the client_id you supplied. " + applicationID
          ),
          false
        );
      } else {
        done(error);
      }
    });
  }),
  function(req, res) {
    //console.log("value of req in request iside auth start" + (req.oauth2.req))
    console.log(
      "value of CustName in request iside auth start" + req.query.CustNo
    );
    var scopeMap = {
      // ... display strings for all scope variables ...
      access_devices: "Access to Mahidra account details",
      create_devices: "create new devices."
    };

    res.render("pages/oauth", {
      transaction_id: req.oauth2.transactionID,
      currentURL: encodeURIComponent(req.originalUrl),
      response_type: req.query.response_type,
      errors: req.flash("error"),
      scope: req.oauth2.req.scope,
      application: req.oauth2.client,
      customerNo: req.query.CustNo,
      redirectURI: req.query.redirect_uri,
      user: req.user,
      map: scopeMap,
      state: req.query.state
    });
  }
);

app.post(
  "/auth/finish",
  function(req, res, next) {
    console.log("/auth/finish inside");
    if (req.user) {
      next();
    } else {
      passport.authenticate(
        "local",
        {
          session: false
        },
        function(error, user, info) {
          console.log("/auth/finish authenting");
          if (user) {
            console.log(user.username);
            req.user = user;
            next();
          } else if (!error) {
            console.log("not authed" + info);
            req.flash(
              "error",
              "Your email or password was incorrect. Please try again."
            );
            res.redirect(req.body["auth_url"]);
          }
        }
      )(req, res, next);
    }
  },
  oauthServer.decision(function(req, done) {
    //console.log("decision user: ", req);
    done(null, { scope: req.oauth2.req.scope });
  })
);

app.post(
  "/auth/exchange",
  function(req, res, next) {
    var appID = req.body["client_id"];
    var appSecret = req.body["client_secret"];

    console.log(req.body);
    console.log(req.headers);
    console.log("Looking for ouath_id = %s", appID);

    oauthModels.Application.findOne(
      { oauth_id: appID, oauth_secret: appSecret },
      function(error, application) {
        if (application) {
          console.log("found application - %s", application.title);
          req.appl = application;
          next();
        } else if (!error) {
          console.log("no matching application found");
          error = new Error(
            "There was no application with the Application ID and Secret you provided."
          );
          next(error);
        } else {
          console.log("some other error, %j", error);
          next(error);
        }
      }
    );
  },
  oauthServer.token(),
  oauthServer.errorHandler()
);

app.post(
  "/command",
  passport.authenticate("bearer", { session: false }),
  function(req, res, next) {
    console.log("Entered");
    console.log(req.user.username);
    console.log(req.body);
    res.send({ userData: req.user });
  }
);

app.put(
  "/services",
  function(req, res, next) {
    console.log("hmm put");
    next();
  },
  passport.authenticate("basic", { session: false }),
  function(req, res) {
    console.log("1");
    if (req.user.username == "admin") {
      console.log("2");
      console.log(req.body);
      var application = oauthModels.Application(req.body);
      application.save(function(err, application) {
        if (!err) {
          res.status(201).send(application);
        } else {
          res.status(500).send();
        }
      });
    } else {
      res.status(401).send();
    }
  }
);

app.get(
  "/services",
  function(req, res, next) {
    console.log("hmm");
    next();
  },
  passport.authenticate("basic", { session: false }),
  function(req, res) {
    if (req.user.username == "admin") {
      oauthModels.Application.find({}, function(error, data) {
        res.send(data);
      });
    }
  }
);

app.options("/testing", function(req, res, next) {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.set("Access-Control-Allow-Credentials", "true");
  res.set("Access-Control-Allow-Headers", "Authorization");
  res.status(200).end();
});

app.get(
  "/testing",
  function(req, res, next) {
    res.set("Access-Control-Allow-Origin", "*");
    next();
  },
  passport.authenticate("bearer", { session: false }),
  function(req, res, next) {
    res.set("Access-Control-Allow-Origin", "*");
    res.send({ test: "sucess" });
  }
);

app.get("/test", (req, res) => {
  var val = req.query.value;
  console.log(val);
  res.end();
});

app.listen(port, () =>
  console.log("***OAuth server running on port " + port + "***")
);
