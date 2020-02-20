process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; //NOT RECOMMENDED, remove once deployed on a HTTPS server
var fs = require("fs");
var url = require("url");
var http = require("http");
//As this was deployed on Heroku, it requires server.js to use http protocol instead of https, uncomment if your host requires https and change http  to https throughout
// var https = require('https');
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
const baseURL = "";
const key = require("./config/key");

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
  console.log(`connecting to MongoDB URL... -> ${mongo_url}`);
});

mongoose_connection.on("error", function(error) {
  console.error("Error in MongoDb connection: " + error);
  //mongoose.disconnect();
});

mongoose_connection.on("connected", function() {
  console.log("MongoDB connected!");
});

mongoose_connection.once("open", function() {
  console.log("MongoDB connection opened!");
});

mongoose_connection.on("reconnected", function() {
  console.log("MongoDB reconnected!");
});

mongoose_connection.on("disconnected", function() {
  console.log("MongoDB disconnected!");
});

mongoose.connect(mongo_url, mongoose_options);

mongoose.set('useFindAndModify', false);
mongoose.set('useCreateIndex', true);


var Account = require("./models/account");
var oauthModels = require("./models/oauth");
var app_id = "https://oauthserver2.herokuapp.com/:" + port; //Change according to host used

var app = express();

app.set("view engine", "ejs");
app.enable("trust proxy");
app.use(express.static('public'));
app.use(morgan("combined"));
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

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/login");
  }
}

app.get("/", function(req, res) {
  res.render("pages/index", { user: req.user, home: true });
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
      res.send(`https://oauthserver2.herokuapp.com/auth/start`); //Change according to host used
    }
  }
);

app.get("/newuser", function(req, res) {
  res.render("pages/register", { user: req.user });
});

app.post("/newuser", function(req, res) {
  Account.register(
    new Account({
      username: req.body.username,
      email: req.body.email,
      mqttPass: "foo"
    }),
    req.body.password,
    function(err, account) {
      if (err) {
        console.log(err);
        return res.status(400).send(err.message);
      }

      passport.authenticate("local")(req, res, function() {
        console.log("created new user %s", req.body.username);
        res.status(201).send();
      });
    }
  );
});

class bufferData{
  constructor(phoneNo, responseS, resOtp, resKey, sentOpt, resData, custId, custName, custEmail, optStat, submittedMpin, clientId, state){
    this.phoneNo = phoneNo
    this.responseS = responseS
    this.resOtp = resOtp
    this.resKey = resKey
    this.sentOtp = sentOpt
    this.resData = resData
    this.custId = custId
    this.custName = custName
    this.custEmail = custEmail
    this.optStat = optStat
    this.submittedMpin = submittedMpin
    this.clientId = clientId
    this.state = state
  }
} 
let data = new bufferData(undefined, undefined, undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined,undefined, undefined, undefined);

app.post("/honda/primary", (primaryreq, res) => {
  // console.log(req)
   data.clientId = primaryreq.body.clientId;
  var scope = primaryreq.body.scope;
  var responseType = primaryreq.body.responseType;
  var redirectURI = primaryreq.body.redirectURI;
  data.state = primaryreq.body.state;
  let phoneNo = primaryreq.body.primaryMobileNo;
  console.log([data.clientId, scope, responseType, redirectURI, data.state]);



  var options = {
    method: "POST",
    url: `${baseURL}/external/alexaVerifyPrimaryContactNo`,
    headers: {
      "Content-Type": "application/json",
      "Authorization": key 
    },
    body: JSON.stringify({ primaryMobileNo: primaryreq.body.primaryMobileNo, emailId: "" })
  };
  console.log("Options " + JSON.stringify(options));
  request(options, function(error, Phoneresponse) {
    console.log("Phoneresponse " + JSON.stringify(Phoneresponse));
    if (error) throw new Error(error);
    let responseS = JSON.parse(Phoneresponse.body);

    app.post('/resendOtp', (req, res)=>{
      let resentOtp=req.body.otp;
      let resentKey=req.body.key;
      // let num = req.body.primaryMobileNo;
      data.resOtp = resentOtp;
      console.log("Resent OTP: ", data.resOtp);
      data.resKey = resentKey;
      console.log("Resent New Key: ", data.resKey);
      res.send({status:200});
    })

    let resOtp =(JSON.parse(Phoneresponse.body)).data.generatedOtp;
    console.log("OTP: ", resOtp);
    data.resKey = (JSON.parse(Phoneresponse.body)).data.key;
    console.log('res key', data.resKey)
  
    if (responseS.data.mpinStatus == false) {
      // setTimeout(res, 2000);
      return res.status(403).render("honda", {
        fail: true,
        otpSent: false, 
        number: primaryreq.body.primaryMobileNo,
        otpVerified: undefined,
        clientId: data.clientId,
        scope: scope,
        redirectURI: redirectURI,
        responseType: responseType,
        state: data.state
      });
    }
    res.render("honda", {
      fail: false,
      otpSent: true,
      number: primaryreq.body.primaryMobileNo,
      otpVerified: undefined
    });
    app.post("/honda/verifyOtp", (req, res) => {
      console.log("value of req in verify otp : " + req)
      let sentOpt = req.body.otp;
      let numberInOTP = req.body.number
      var options = {
        method: "POST",
        url: `${baseURL}/external/alexaVerifyOtpPin`,
        headers: {
          "Content-Type": "application/json",
          "Authorization": key
        },
        body: JSON.stringify({
          key: data.resKey,
          otp: sentOpt,
          emailId: "",
          primaryMobileNo: req.body.number,
          customerId: "",
          customerCategory: ""
        })

      };
      console.log("options in verifyotp: " +JSON.stringify(options))
      request(options, async function(error, response) {
        if (error) throw new Error(error);
        console.log("response " + JSON.stringify(response))
        let resData = JSON.parse(response.body);
        console.log("res data " + resData)
        let custId = resData.data.loginInfo.customerId;
        let custName = resData.data.loginInfo.firstname;
        let custEmail = resData.data.loginInfo.emailId;
        let optStat = resData.data.otpStatus;

        console.log("cust email from res data: " + custEmail);
        console.log("data" + JSON.stringify(data))
        console.log("Res data: ", resData);
       data.phoneNo = resData.data.primaryMobileNo
      
        if (optStat == "False") {
          return res.render("honda", {
            fail: false,
            otpSent: true,
            number:numberInOTP,
            otpVerified: false
          });
        }
        let checkUser = await account.findOne({ email: custEmail });
        if (!checkUser) {
          var options = {
            method: "POST",
            url: `https://oauthserver2.herokuapp.com/newuser`,
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            form: {
              username: custName,
              email: custEmail,
              password: custId
            }
          };
          request(options, function(error, response) {
            if (error) throw new Error(error);
            console.log(response.body);
          });
        }

        console.log("value of number for mpin page " +  numberInOTP)
        res.render("honda", {
          fail: undefined,
          otpSent: undefined,
          number:numberInOTP,
          otpVerified: true,
          mpinVerified: undefined
        });

        app.post("/honda/verifyMpin", (req, res) => {
          let submittedMpin = req.body.mpin;

          console.log("value of number in mpin page " +  req.body.number)
          /*var  options = {
            method: "POST",
            url: `${baseURL}/authentication/loginApi`,
            headers: {
              "Content-Type": "application/json",
              mpin: submittedMpin,
              customerId: custId,
              customerCategory: "Primary"
            },
            body: JSON.stringify({ emailId: "", primaryMobileNo: data.phoneNo })
          }; */
          var options = { 
            'method': 'GET',
            'url': `${baseURL}/external/login`,
            'headers': {
            'mpin': submittedMpin,
            'Content-Type': 'application/json',
            'primaryMobileNo':  req.body.number,
            "Authorization": key
            }
            };  
            console.log("Options: ", options);
          request(options, async function(error, response) {
            console.log(response.headers);
            if (error) throw new Error(error);
         let   responseS = JSON.parse(response.body);
         console.log("Val of responses: ", responseS);
         console.log("val of email for auth login " +  responseS.data.customerDetails.email)
            if (responseS.status.status == true) {
              let checkIfData = await account.findOne({ email: responseS.data.customerDetails.email });
              console.log("value of checkIfData" + checkIfData);

              if (!checkIfData.data) {  
                await account.findOneAndUpdate( 
                  { email: responseS.data.customerDetails.email },  
                  {
                    $set: {
                      mpin: submittedMpin,
                      data: responseS.data,
                      status: responseS.status,
                      accessToken: response.headers.alexarefreshtoken,
                      refreshToken: response.headers.alexaaccesstoken
                    }
                  }
                );
              }else{
                await account.findOneAndUpdate(
                  { email: responseS.data.customerDetails.email },
                  {
                    $set: {
                      mpin: submittedMpin, 
                      data: responseS.data,
                      status: responseS.status,
                      accessToken: response.headers.alexarefreshtoken,
                      refreshToken: response.headers.alexaaccesstoken
                    }
                  }
                );
              }

              console.log("custname before auth login: " + responseS.data.customerDetails.firstname)
              console.log("custId before auth login: " + responseS.data.customerDetails.customerId)
              var options = {
                method: "POST",
                url: `https://oauthserver2.herokuapp.com/login`,
                headers: {
                  "Content-Type": "application/x-www-form-urlencoded"
                },
                form: {
                  username: responseS.data.customerDetails.firstname,
                  password: responseS.data.customerDetails.customerId
                }
              };
              request(options, function(error, response, body) {
                if (error) throw new Error(error);
                console.log(
                  "value of login response after post" + JSON.stringify(body)
                );
                res.redirect(
                  `${response.body}?scope=${scope}&client_id=${data.clientId}&redirect_uri=${redirectURI}&response_type=${responseType}&CustName=${responseS.data.customerDetails.firstname}&CustId=${responseS.data.customerDetails.customerId}&state=${data.state}`
                );
                  for (var member in data) delete data[member]
              });
            } else {
              res.render("honda", {
                fail: undefined,
                otpSent: undefined,
                number: data.phoneNo,
                otpVerified: true,
                mpinVerified: false
              });
            }
          });
        });
      });
    });
  });
});

app.get("/honda/primary", (req, res) => {
  //console.log("honda primary get request" + JSON.stringify( req));
  res.render("honda", {
    fail: false,
    otpSent: false,
    otpVerified: undefined,
    clientId: req.query.client_id,
    responseType: req.query.response_type,
    redirectURI: req.query.redirect_uri,
    scope: req.query.scope,
    state: req.query.state
  });
});

app.get(
  "/auth/start",
  oauthServer.authorize(function(applicationID, redirectURI, done) {
    console.log("applicationID " + applicationID)
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
      "value of CustName in request iside auth start" + req.query.CustName
    );

    console.log(
      "value of CustId in request iside auth start" + req.query.CustId
    );
    var scopeMap = {
      // ... display strings for all scope variables ...
      access_devices: "Access to Honda Connect account",
      create_devices: "create new devices."
    };

    res.render("pages/oauth", {
      transaction_id: req.oauth2.transactionID,
      currentURL: encodeURIComponent(req.originalUrl),
      response_type: req.query.response_type,
      errors: req.flash("error"),
      scope: req.oauth2.req.scope,
      application: req.oauth2.client,
      customerId: req.query.CustId,
      customerName: req.query.CustName,
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

var server = http.Server(app);
// if (app_id.match(/^http:\/\/localhost:/)) {
// 	var options = {
// 		key: fs.readFileSync('server.key'),
// 		cert: fs.readFileSync('server.crt')
// 	};
// 	server = http.createServer(options, app);
// }

server.listen(port, host, function() {
  console.log("App listening on  %s:%d!", host, port);
  console.log("App_ID -> %s", app_id);

  setTimeout(function() {}, 5000);
}); 
 