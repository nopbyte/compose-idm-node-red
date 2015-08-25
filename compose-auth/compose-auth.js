/*
How to test this..

Authenticate the user first.
curl   -H "Content-Type: application/json;charset=UTF-8" -d '{"username":"test2","password":"pass"}' -X POST http://localhost:8080/auth/user/

Copy the token in the environment variable TOKEN...
TOKEN=....

curl -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json;charset=UTF-8" -X GET http://localhost:1880/a
*/


module.exports = function(RED) {
    "use strict";
    var http = require("follow-redirects").http;
    var https = require("follow-redirects").https;
    var urllib = require("url");
    var express = require("express");
    var getBody = require('raw-body');
    var mustache = require("mustache");
    var querystring = require("querystring");
    var cors = require('cors');
    var jsonParser = express.json();
    var urlencParser = express.urlencoded();
    var request = require('request');
    var url = require('url');


    var map = new Object();
    var my_url= 'http%3A%2F%2Flocalhost%3A1880%2Fb';


    //get expiration of the token
    function getExpirationFromToken(token){
   	var split = token.split(".");
	for(var i=0; i< split.length; i++){
        	var buf = new Buffer(split[i], 'base64');
	        var object = JSON.parse(buf.toString());
        	if(object.exp != null && object.exp != undefined){
                     return object.exp;
	        }
    	}
    }

    //improve this...
    function getValueCookie(msg,label){
        console.log('second stuff:'+msg);
	var str = msg.req.get('Cookie');
	if(str != undefined && str != null){
	  var res = str.split(";");
          for(var i =0; i<res.length; i++){
		var cookies2 = res[i].split('=');
		for(var j=0; j<cookies2.length; j++){
			if(cookies2[j] == label){
				return cookies2[j+1];
			}
		}
	  }
	}
    }
  
   function getTokenByCode(cookie,code, node, msg, callback){
		if(map[cookie]!= null && map[cookie] != undefined && map[cookie]['status'] == 0){
			request.post(
			   node.url+'/oauth/token',
			       { form: { 
					code: code, 
				  	redirect_uri: my_url, 
					grant_type: 'authorization_code', 
					client_id: 'someid', 
					client_secret: 'some_secret'
				    },
				 headers: {
			          'Authorization': 'Basic dGVzdDM6cGFzcw==',
			         }				 
			       },
			       function (error, response, body) {
			        if (!error && response.statusCode == 200) {
				    callback(JSON.parse(body)['access_token']);
			        }
				else{
					console.log('problem with auth. Message: '+response+' body: '+body);
					bounce(cookie,msg,node);
				}
			    }
			);			
		}
		else{			
			bounce(cookie,msg,node);
		}
		
   }

   function  getAttributesByToken(map,cookie, node, msg,token){
	var options = {
                        url: node.url+'/idm/user/info/',
                        headers: {'Authorization': "bearer "+token}                               
        };	
	request.get(options,
                        function (error, response, body) {
                                  if (!error&&response.statusCode ==200) {
                                          map[cookie]['attributes'] = JSON.parse(body);
                                          //map[cookie]['timestamp'] = body['lastModified'];
                                          keepGoing(node, msg, cookie);
                                  }
                                  else{
                                        bounce(cookie,msg,node);
                                  }
			}
        );
   }

   function authenticated(cookie){
	if( map[cookie]!= null && map[cookie] != undefined && map[cookie]['status'] == 1){
		return 1;
	}
	return 0;
   }

   // TODO fix configuration of my_url?? clarify with others, how this work???

    function bounce(cookie,msg, node){
      map[cookie] = {status: 0};
      msg.res.redirect(node.url+'/oauth/authorize?redirect_uri='+my_url+'&scope=&state=&response_type=code&client_id=test3');
    }
   
    function keepGoing(node, msg,cookie){
      msg.payload = map[cookie]['token'];
      node.idm = {"attributes":map[cookie]['attributes'],  "token": map[cookie]['token'],"timestamp":map[cookie]['attributes']['lastModified']};
      console.log("idm info:"+JSON.stringify(node.idm));

      node.send(msg);
    }
    // verify that token and user actually match... TODO
    function userMatches(idmInfo, callback){
	callback();
    }

    function LowerCaseNode(config) {

        RED.nodes.createNode(this,config);
        var node = this;
	console.log("config: "+JSON.stringify(config));
	this.url = config.url;
	console.log("using idm:"+this.url);

         this.on('input', function(msg) {
	    if(node.idm != undefined){
		
		userMatches(node.idm, function(map,msg,node){
		var cookie = Math.floor((Math.random()*1000000000 ) + 1);		
		map[cookie] = node.idm;		
 		keepGoing(node,msg,cookie);
              });

            }
            var cookie = getValueCookie(msg,'user_cookie_id');
	    if(cookie !=null && cookie != undefined && authenticated(cookie)){
		 keepGoing(node, msg,cookie);
	    }
	    else if(cookie != null && cookie != undefined){
		//cookie set.. maybe it comes with code from IDM?
		var code = msg.req.query.code;
            	if(code != undefined && code != null){
			  getTokenByCode(cookie,code, node, msg, function(token){
				if(token != undefined && token !=null){
					map[cookie] = {status:1, token: token}; // here he is authenticated
					getAttributesByToken(map,cookie, node, msg,token);
				}
				else{

					bounce(cookie,msg,node);
				}
		        	console.log('code'+msg.req.query.code);
		   	 });
            	}else{
			//has a cookie, but he doesn't bring a code?? send it back!
			bounce(cookie,msg,node);
           	}
	    }else{
	 	// no cookie, so set one and send him to IDM   
		var cookie = Math.floor((Math.random()*1000000000 ) + 1);
		console.log('map with'+JSON.stringify(map));
		msg.res.setHeader( 'Set-Cookie', 'user_cookie_id='+cookie );
		bounce(cookie,msg,node);

	        //msg.res.send('hi');
                //node.send(msg);
	   }
        });
    }
    RED.nodes.registerType("compose-auth",LowerCaseNode);
}




