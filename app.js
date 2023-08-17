require('dotenv').config();
//recommended to write at the top.
const express=require("express");
const bodyParser=require("body-parser");
const mongoose=require("mongoose");
const session=require("express-session")
const passport=require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
/*its a new constant called googlestrategy and it uses the passport-google-oauth20 package that we installed just now
and we're going to use it as a passport strategy.*/
const findOrCreate = require("mongoose-findorcreate");
//we don't need to require passport-local separately as it will be required by passport-local-mongoose.
// import bcrypt from "bcrypt";
// const saltRounds = 10;
//4th level authentication by hashing and salting basically jo password user daalega
//usme thoda sa random dta ya salt daalke uska hash banega jo ki secure hoga
//bcrypt aur saltrounds dono 4th level authentication ke part hain.

/*cookies add krne ke liye passport ka use krenge uske liye humne install kiya npm packages
that are passport, express-session, passport-local, passport-local-mongoose*/

//import md5 from "md5";
//3rd level authentication


//import encrypt from "mongoose-encryption";
//2nd level authentication.


/*OAuth matlab open authorisation jisme hum sign in ith google sign in with facebook ka use krte hain joki
jab hum inpe click krte hain to ye get request krte hain unpar fir unke databse se username password humare database se compare krte hain
jaise mene koi bracebook banaya jisme koi agar isme facebook ke through login kre to facebook ke databse se match hone wale
username password jo mere database mein hain vo mere user ke friends list mein add ho jaaye*/

const app = express();



app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended:true}));

///////////////////////////////Step 1
app.use(session({
    secret:"Our little secret.",
    resave: false,
    saveUninitialized: false,
}));
//////////////////////////Step 2 right after we initializedor used the session.
app.use(passport.initialize());
//initialized the passport

////////////////////////////Step 3
app.use(passport.session());

mongoose.connect("mongodb://0.0.0.0:27017/userDB");

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    //jab ye googleId added nahi tha tab findby id mein vo har baar naya user create kr rha tha isliye ye add kra.
    secret:String
});

//////////////////////////////////////Step 4
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//yahan humne passportlocalmongoose plugin use kiya hai


/*after adding new mongoose.Schema,we can say that this user schema is no longer
just a simple javascript object but it's actually an object created from the
mongoose schema class*/
//ye hum level 1 encryption ke liye kr rhe hain taaki user ka password encrypt yaani safe rkh ske.

/*there are two ways for encrypting in npmjs.com documentation for mongoose encryption
one way is to create encryption key and assigning key.Alternatively and the one that we're going to use will be a little bit later down
in the documentation and it is a convinient method of defining a secret which is simply a long string and
we are going to use that secret to encrypt our database.*/

//////////////////////PLUGIN METHOD///////////////////

//userSchema.plugin(encrypt, { secret: process.env.SECRET ,encryptedFields: ["password"]});
//ye .env use krna is 2nd level authentication
//yahan process.env.SECRET mene env file se data lene ke liye likha hai
/*ab humne ye kr to diya but ye humara poora database encrypt kr dega but we may or may not want that kind of behaviour
for our database because later on when the user logs in we are going to have to search through our database to find their email address.
So its best to encrypt only the password field and to do that we have change some options in this plugin and we can see in the npm mongoose encryption docs
we are going to use encrypt only certain fields jisme hume plugin ke andar encryptedFields daalna padega.*/
/*it is important that we add this plugin to the schema before you create your mongoose model because we can see that we're passing
in the userSchema as a parameter to create our new Mongoose model that is the user model
but before that we are going to add our encrypt package as a plugin(refer plugin documentation on mongoose documentation).plugins are just extra bits of packaged code that you can add to the mongoose schemas to extend their functionality or give them more powers
essentially.*/

//aur hume aur kuch change krne ki jarurat nahi hai login aur register pages mein
//kyuki ye khud hi decrypt kr dega jab hum find krenge aur khud hi encrypt kr dega jab hum register krenge.


//third level authentication is using hash matlab
//password ko hash mein store krenge fir jab login hoga tab vo vapas hash banega
//agar dono hash match matlab password sahi aur ye md5 npm package se hoga

const User = new mongoose.model("User",userSchema);

///////////////////////////////////Step 5
/*so right below where we've created our user mongoose model and
setup mongoose to use that schema that we created earlier on,we're ready to
configure the very last thing which is the passport local configurations and we're going to use exactly
the same as what the documentation in npmjs.com tells us to do which is to create
a strategy which is going to be the local strategy to authenticate users using their
username and password and also to serialize and deserialize our user. Now the serialize and
deserialize is only necessary when we're running sessions and what is does is when we tell it to 
serialize our user it basically creates that fortune cookie and stuffs the message namely our users identifications into the
cookie and when we deserialize it basically allows passport to be able to crumble the cookie
and discover the message inside which is who this user is and all of their identification so that we can authenticate
them on our server.*/
passport.use(User.createStrategy());

passport.serializeUser(function(user,done){
    done(null,user.id);
});

passport.deserializeUser(function(id,done){
    User.findById(id).then(function(user){
        done(null,user);
    }).catch(function(err){
        done(err);
    })
});
////////////////step 5 end

//ye passport.use mene serialize deserialize ke baad hi lagaye hain varna chalega nahi.
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //this callback URL hits up a path on our server at /auth/google/secrets.
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    //ye google+ ki deprecation ki vajah se lagaya hai
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        //yahan ye findOrCreate ek pseudo code ki tarah likha gaya hai ise implement krna padega.
        //we will use an npm package like mongoose-findOrCreate
      return cb(err, user);
    });
  }
));


app.get("/",(req,res)=>{
    res.render("home.ejs");
});

app.get("/auth/google",
    passport.authenticate("google",{ scope : ["profile"] })
);
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });
/*if we take a look at the documentation of passportjs.org we can see they provided an example how to set up means ki jab 
sign in with google pe main click krta hu tab account choose krne par cannot get error aati hai 
kyuki uska get route nahi lagaya hai to uska procedure ye hai.
So it's again going to be an app.get and this get request gets made by google when they try to redirect the user
back to our website and the string "auth/google/callback" has to match what we specified to google previously.
and then we will authenticate the user locally and if there were any problems we're going to send them back to the
login page again else we can redirect them to the secrets page or any other sort of privileged page.*/
app.get("/login",(req,res)=>{
    res.render("login.ejs");
});

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});

/////////////part of passport based authentication
app.get("/secrets",(req,res)=>{
    // if(req.isAuthenticated()){
    //     //yahan humne check kiya ki authenticate kiya ya nahi
    //     res.render("secrets.ejs");
    // }
    // else{
    //     res.redirect("/login");
    // }
    User.find({"secret":{$ne: null}},).then(function(foundUsers){
        if(foundUsers){
            res.render("secrets.ejs",{usersWithSecrets: foundUsers});
        }
    }).catch(function(err){
        console.log(err);
    })
});

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        //yahan humne check kiya ki authenticate kiya ya nahi
        res.render("submit.ejs");
    }
    else{
        res.redirect("/login");
    }
    
});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;

    //console.log(req.user);
    User.findById(req.user.id).then(function(foundUser){
        foundUser.secret=submittedSecret;
        foundUser.save();
        res.redirect("/secrets");
    }).catch(function(err){
        console.log(err);
    })
})

app.get("/logout",(req,res)=>{
    //now we will deauthenticate our user and then logout.so for that you can refer
    //the passportjs.org documentation for logout.
    req.logout(function(err) {
        if (err) { 
            console.log(err);
        }
        else{
            res.redirect("/");
        }
      });
});

/*IMPORTANT THING*/
//If i edit my code in app.js or if I restart my server the cookies will get deleted
//and the session gets restarted. 

app.post("/register",(req,res)=>{
    // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    //     //ye npmjs.com documentation se dekha bcrypt ka
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash,
    //         //level 4 authentication
    //         //so yaha pe vo hash jo generate hoga salt ke saath vo aayega

    //         //password: md5(req.body.password)
    //         //level 3 authentication
    //     });
    //     newUser.save().then(function(){
    //         res.render("secrets.ejs");
    //     }).catch(function(err){
    //         console.log(err);
    //     });
    // });
    /////////ye user.register npmjs documentation mein passport local mongoose wale section se uthaya hai
    User.register({username: req.body.username},req.body.password,function(err,user){
        if(err)
        {
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
                //abhi authenticate nahi hua hai abhi secrets route pe jaayega fir authenticate hoga.
                /*now notice that previously we never had a secrets route because
                we always relied on res.render secrets page either through register or through login
                but in this case because we are authenticating our user and setting up a logged in session for them then even if they just go
                directly to the secret page they should automatically be able to view it if they are still logged in. So that's why we need to create our secrets route.*/
            });
        }
    });
    /*this register method comes from the passport-local-mongoose package and its only because
    of the package that we can avoid creating our new user, saving our user and interacting with Mongoose directly.Instead
    we are going to be using the passport-local-mongoose package as our middleman to handle all of that
    for us.*/
});


app.post("/login",(req,res)=>{
    // const username = req.body.username;
    // const password = req.body.password;

    // //const password = md5(req.body.password);
    // //converted the input password to hash and then comparing
    // //3rd level authentication
    // User.findOne({email: username}).then(function(foundUser){
    //     //ye if wali condition ki jagah hum bcrypt.compare use krenge password check krne ke liye

    //     bcrypt.compare(password, foundUser.password, function(err, result) {
    //         /*we are passing password in this compare function against
    //         the hash that we've got stored in our database which is stored inside
    //         the foundUser.password field*/
    //         if(result === true)
    //         {
    //             res.render("secrets.ejs");
    //         }
    //     });

    //     /*if(foundUser.password === password)
    //     {
    //         res.render("secrets.ejs");
    //     }*/
    // }).catch(function(err){
    //     console.log(err);
    // })
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    //ab login mein passport use krne ke liye login function ka use krenge
    //jo req.login se chalega ye passportjs.org documentation mein dekh skte hain.
    req.login(user,function(err){
        if(err)
        {
            console.log(err);
        }else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });

});


app.listen(3000,(req,res)=>{
    console.log("Server started on port 3000.");
});