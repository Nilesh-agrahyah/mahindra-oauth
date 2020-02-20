var oauth2orize = require("oauth2orize");
var OAuth = require("./models/oauth");
var User = require("./models/account");
var request = require("request");
const baseURL = "https://testapi.hondaconnect.in/bos";
var server = oauth2orize.createServer();
  

server.grant(
  oauth2orize.grant.code(
    {
      scopeSeparator: [" ", ","]
    },
    function(application, redirectURI, user, ares, done) {
      //console.log("grant user: ", user);

      OAuth.GrantCode.findOne(
        { application: application, user: user },
        function(error, grant) {
          if (!error && grant) {
            done(null, grant.code);
          } else if (!error) {
            var grant = new OAuth.GrantCode({
              application: application,
              user: user,
              scope: ares.scope
            });
            grant.save(function(error) {
              done(error, error ? null : grant.code);
            });
          } else {
            done(error, null);
          }
        }
      );

      // var grant = new OAuth.GrantCode({
      // 	application: application,
      // 	user: user,
      // 	scope: ares.scope
      // });
      // grant.save(function(error) {
      // 	done(error, error ? null : grant.code);
      // });
    }
  )
);

server.exchange(
  oauth2orize.exchange.code(
    {
      userProperty: "appl"
    },
    function(application, code, redirectURI, done) {
      OAuth.GrantCode.findOne({ code: code }, function(error, grant) {
        if (grant && grant.active && grant.application == application.id) {
          console.log("grantcode exists");
          console.log("grant" + JSON.stringify(grant));
          var now = new Date().getTime();
          OAuth.AccessToken.findOne(
            {
              application: application,
              user: grant.user,
              expires: { $gt: now }
            },
            async function(error, token) {
              console.log("accesstoken schema exists");

              if (token) {
                console.log("token is there");
                OAuth.RefreshToken.findOne(
                  { application: application, user: grant.user },
                  function(error, refreshToken) {
                    if (refreshToken) {
                      //var expires = token.expires -  (new Date().getTime());
                      var expires = Math.round(
                        (token.expires - new Date().getTime()) / 1000
                      );
                      done(null, token.token, refreshToken.token, {
                        token_type: "Bearer",
                        expires_in: expires
                      });
                      console.log("sent expires_in: " + expires);
                    } else {
                      // Shouldn't get here unless there is an error as there
                      // should be a refresh token if there is an access token
                      done(error);
                    }
                  }
                );
              } else if (!error) {
                console.log("token is not there and no error");
                console.log("User  " + JSON.stringify(User));
                let data = await User.findById(grant.user);
                if (data) {
                  console.log("access token of the user " + data.accessToken);
                }

                var token = new OAuth.AccessToken({
                  token: data.accessToken,
                  application: grant.application,
                  user: grant.user,
                  grant: grant,
                  scope: grant.scope
                });

                token.save(function(error) {
                  var expires = Math.round(
                    (token.expires - new Date().getTime()) / 1000
                  );
                  //delete old refreshToken or reuse?
                  OAuth.RefreshToken.findOne(
                    { application: application, user: grant.user },
                    function(error, refreshToken) {
                      if (refreshToken) {
                        done(
                          error,
                          error ? null : token.token,
                          refreshToken.token,
                          error
                            ? null
                            : {
                                token_type: "Bearer",
                                expires_in: expires,
                                scope: token.scope
                              }
                        );
                      } else if (!error) {
                        console.log(
                          "refresh token of the user " + data.refreshToken
                        );
                        var refreshToken = new OAuth.RefreshToken({
                          token: data.refreshToken,
                          user: grant.user,
                          application: grant.application
                        });

                        refreshToken.save(function(error) {
                          done(
                            error,
                            error ? null : token.token,
                            refreshToken.token,
                            error
                              ? null
                              : {
                                  token_type: "Bearer",
                                  expires_in: expires,
                                  scope: token.scope
                                }
                          );
                        });
                      } else {
                        console.log("error" + error);
                        done(error);
                      }
                    }
                  );
                });
                console.log("value of token " + JSON.stringify(token));
              } else {
                console.log("error" + error);
                done(error);
              }
            }
          );
        } else {
          done(error, false);
        }
      });
    }
  )
);

server.exchange(
  oauth2orize.exchange.refreshToken(
    {
      userProperty: "appl"
    },
    function(application, token, scope, done) {
      console.log("Yay! refreshing");
      console.log("token in request" + token);
      OAuth.RefreshToken.findOne({ token: token }, function(error, refresh) {
        console.log("refresh token found");
        if (refresh && refresh.application == application.id) {
          console.log("refresh token matches application");
          OAuth.GrantCode.findOne({user : refresh.user}, async function(error, grant) {
            console.log(
              "refresh token matches application, user and grant code found"
            );
            if (grant && grant.active && grant.application == application.id) {
              console.log(
                "refresh token matches application and grant code found and active"
              );
              let data = await User.findById(grant.user);
              console.log("data " + data);
              //TODO: We may need a different API without user MPIN
              var options = {
                method: "GET",
                url: `${baseURL}/external/getAlexaRefreshToken`,
                headers: {
                  "Content-Type": "application/json",
                  customerId: data.data.customerDetails.customerId, 
                  alexaaccessToken: data.refreshToken
                }
              };
              console.log("Value of options: " + JSON.stringify(options));
              request(options, function(error, response) {
                if (error) {
                  console.log("error in getting new token from honda " + error);
                  throw new Error(error);
                } else {
                  console.log(
                    "got response from honda fr refresh " +
                      JSON.stringify(response)
                  );
                  var newToken = new OAuth.AccessToken({
                    token: response.headers.alexarefreshtoken,
                    application: refresh.application,
                    user: refresh.user,
                    grant: grant,
                    scope: grant.scope
                  });
                  console.log("saving new token");
                  newToken.save(function(error) {
                    var expires = Math.round(
                      (newToken.expires - new Date().getTime()) / 1000
                    );
                    console.log("expires " + expires);
                    if (!error) {
                      console.log("token saved");
                      done(null, newToken.token, refresh.token, {
                        token_type: "Bearer",
                        expires_in: expires,
                        scope: newToken.scope
                      });
                    } else {
                      console.log("token saving error " + error);
                      done(error, false);
                    }
                  });
                }
              });
            } else {
              console.log(
                "refresh token matches application and grant code not found and active"
              );
              done(error, null);
            }
          });
        } else {
          console.log("refresh token does not match application");
          //console.log("refresh token matches application and grant code found and active")
          done(error, false);
        }
      });
    }
  )
);

server.serializeClient(function(application, done) {
  done(null, application.id);
});

server.deserializeClient(function(id, done) {
  OAuth.Application.findById(id, function(error, application) {
    done(error, error ? null : application);
  });
});

module.exports = server;
