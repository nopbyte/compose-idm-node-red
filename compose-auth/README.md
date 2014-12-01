compose-idm-node-red
====================

This repo contains node-red extensions communicating with compose-idm

#Testing it


Open the file example-flow.txt, copy it to clipboard and import it to Node-red, and click on Deploy.

Then authenticate the user first with COMPOSE-IDM by setting the location of IDM in the IDM_HOST variable, and placing username, and password in the following curl line.

	IDM_HOST=http://
	curl   -H "Content-Type: application/json;charset=UTF-8" -d '{"username":"test2","password":"pass"}' -X POST $IDM_HOST/auth/user/

Copy the token in the environment variable TOKEN...

	TOKEN=....
Call your http input node from curl like this (assuming your url in node is)

	curl -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json;charset=UTF-8" -X GET http://localhost:1880/my_input_node

