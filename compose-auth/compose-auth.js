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


    function LowerCaseNode(config) {
        RED.nodes.createNode(this,config);
        var node = this;
	console.log("config: "+JSON.stringify(config));
	this.url = config.url;
	console.log("using idm:"+this.url);

         this.on('input', function(msg) {
	    this.log(msg.res);
	   //};
	    // check for bearer
	    if(msg.req.get('Authorization')==undefined)
	    {
	      	//msg.res.redirect('http://www.google.com');
		msg.res.status(401);
		msg.res.send("Please provide an Authorization header including the format \"Bearer TOKEN\" ");
	    }
	    else{

		var options = {
	    		url: this.url+'/idm/user/info/',
	    		headers: {
	        		'Authorization': msg.req.get('Authorization') 				}		
		};
   		
		request.get(options,
    	    			function (error, response, body) {
 	       			  if (!error) {
					if(response.statusCode ==200)            						{
					 node.log("user_info:"+JSON.stringify(body));
					 console.log(body)
					 msg.user_attributes = body;
				         node.send(msg);
				 	}
					else{
					 msg.res.status(response.statusCode)
					 {
					  msg.res.send(body);
					 }
					}	
        		  	  }
    				}
		         );
	    }
	    //msg.res.send("done");
            //msg.payload = msg.payload.toLowerCase();
            //node.send(msg);
        });
    }
    RED.nodes.registerType("compose-auth",LowerCaseNode);
}



