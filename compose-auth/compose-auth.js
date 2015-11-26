/*
How to test this..

Authenticate the user first.
curl   -H "Content-Type: application/json;charset=UTF-8" -d '{"username":"test2","password":"pass"}' -X POST http://localhost:8080/auth/user/

Copy the token in the environment variable TOKEN...
TOKEN=....

curl -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json;charset=UTF-8" -X GET http://localhost:1880/a
*/

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


module.exports = function(RED) {
    "use strict";

    var tokenMap = new Object();


    var map = new Object();
    
    function getUrl(msg){
		return encodeURIComponent(msg.req.protocol+'://'+msg.req.headers.host+"/api"+msg.req.url);
    }

    function isExpired(token){
        if (token == undefined){
                return true;    
        }
	else if(token == 'anonymousToken'){
		return false;
	}
        var time = parseInt((new Date).getTime())/1000;
        var tokentimeObj = getExpirationFromToken(token);
	if(tokentimeObj != null && tokentimeObj != undefined){
        	var tokentime = parseInt(tokentimeObj);
	        var diff = (tokentime + 350) - time; //difference minus 5 minutes...in case there is some difference
	        //console.log('current time:'+time);
	        //console.log('expiration time:'+tokentime);
	        //console.log('difference :'+diff);
                return diff<0;
	}
	else{
		//console.log("can not find token time");
		return true;
	}
    }



    function getExpirationFromToken(token){
       try{
	 var split = token.split(".");
         for(var i=0; i< split.length; i++){
                var buf = new Buffer(split[i], 'base64');
                var object = JSON.parse(buf.toString());
                if(object.exp != null && object.exp != undefined){
                     return object.exp;
                }
         }
	}catch(error){
		//console.log("error decoding token...");
	}
	return undefined;
    }


    //improve this...
    function getValueCookie(msg,label){
      if(msg.req){
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
      return null;
    }
  
   function getTokenByCode(cookie,code, node, msg, callback){
		if(map[cookie]!= null && map[cookie] != undefined && map[cookie]['status'] == 0){
			request.post(
			   node.url+'/oauth/token',
			       { form: { 
					code: code, 
				  	redirect_uri: getUrl(msg), 
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
					//console.log('problem with auth. Message: '+JSON.stringify(response)+' body: '+JSON.stringify(body));
					bounce(cookie,msg,node);
				}
			    }
			);			
		}
		else{			
			bounce(cookie,msg,node);
		}
		
   }

   function  getAttributesByToken(cookie, node, msg,token){
	//console.log('atts by token');
	var options = {
                        url: node.url+'/idm/user/info/',
                        headers: {'Authorization': "bearer "+token}                               
        };	
	request.get(options,

                        function (error, response, body) {
                                  if (!error&&response.statusCode ==200) {
					//console.log("satus code with attributes OK");
					if(cookie != undefined && cookie != null){
					  //console.log(" cookie is there ");
                                          map[cookie]['attributes'] = JSON.parse(body);
                                          keepGoing(node, msg, cookie);
					}
					else{
					  //console.log("no cookie?");
                                          tokenMap[token] = new Object();
					  tokenMap[token]['attributes'] = JSON.parse(body);
                                          keepGoingToken(node, msg, token);
					}
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


    function sendErrorback(msg,errorDescription){
		 msg.res.status(403)
                  msg.res.send({error:errorDescription});

    }

    function bounce(cookie,msg, node){
      map[cookie] = {status: 0};
      if(msg.res){
         msg.res.redirect(node.url+'/oauth/authorize?redirect_uri='+getUrl(msg)+'&scope=&state=&response_type=code&client_id=test3');
      }
    }

    function keepGoingToken(node, msg,token){
      if(typeof(msg.payload)  != 'object' || msg.payload == null){
            var old = msg.payload;
            msg.payload = {'oldpayload':old};       
      } 
      msg.payload.token = token;
      node.userInfo = tokenMap[token]['attributes'];
      node.userInfo["token"]= token;
      node.userInfo["timestamp"] = tokenMap[token]['attributes']['lastModified'];

      node.send(msg);
    }
   
   
    function keepGoing(node, msg,cookie){
      msg.payload.token = map[cookie]['token'];
      node.userInfo = map[cookie]['attributes'];
      node.userInfo ["token"] =  map[cookie]['token'];
      node.userInfo["timestamp"] = map[cookie]['attributes']['lastModified'];
      node["cookie"] =cookie;

      node.send(msg);
    }

    // verify that token and user actually match... TODO
    function userMatches(idmInfo, callback){
        
	callback();
    }

    function authNode(config) {
        var node = this;
        RED.nodes.createNode(this,config);
	//console.log("config: "+JSON.stringify(config));
	this.url = config.url;
	//console.log("using idm:"+this.url);
	
         this.on('input', function(msg) {
	     /*if(node.idm != undefined){		
	     	userMatches(node.idm, function(map,msg,node){
  	     	var cookie = Math.floor((Math.random()*1000000000 ) + 1);		
      	       map[cookie] = node.idm;		
 	     	keepGoing(node,msg,cookie);
                 });
              }*/


            var cookie = getValueCookie(msg,'user_cookie_id');
	    if(msg.token || (msg.req && (msg.req.headers.authorization))){	
	       var token = "";
          	if(msg.token){
                 	token = msg.token;
          	}
		else  if(msg.req.headers.authorization != undefined && msg.req.headers.authorization != null){
			token = msg.req.headers.authorization;	
		}
		token = token.replace("bearer","");
                token = token.replace("Bearer","");
                token = token.trim();
                console.log('trimmed token value: '+token);

		if(!isExpired(token) && tokenMap[token] != undefined && tokenMap[token] != null){
			 console.log('token found previously');
			 keepGoingToken(node,msg,token);		
		}
		else if(isExpired(token)){
   			sendErrorback(msg,'either your token expired, or it has the wrong format');
		}
		else{
			console.log('token is not  in cache...');
			console.log("auth header received: "+token);
			getAttributesByToken(null, node, msg,token);
		}
	    }
	    else if(cookie !=null && cookie != undefined && authenticated(cookie)){
		 keepGoing(node, msg,cookie);
	    }
	    else if(cookie != null && cookie != undefined){
		//cookie set.. maybe it comes with code from IDM?
		var code = msg.req.query.code;
            	if(code != undefined && code != null){
			  getTokenByCode(cookie,code, node, msg, function(token){
				if(token != undefined && token !=null){
					map[cookie] = {status:1, token: token}; // here he is authenticated
					getAttributesByToken(cookie, node, msg,token);
				}
				else{

					bounce(cookie,msg,node);
				}
		        	//console.log('code'+msg.req.query.code);
		   	 });
            	}else{
			//has a cookie, but he doesn't bring a code?? send it back!
			bounce(cookie,msg,node);
           	}
	    }else{
	 	// no cookie, so set one and send him to IDM   
		var cookie = Math.floor((Math.random()*1000000000 ) + 1);
		//console.log('map with'+JSON.stringify(map));
		if(msg.res){
			msg.res.setHeader( 'Set-Cookie', 'user_cookie_id='+cookie );
		}
		bounce(cookie,msg,node);

	   }
        });
    }
    RED.nodes.registerType("compose-auth",authNode);
}




