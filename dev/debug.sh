mkdir temp_client
mkdir temp_server

cp -r ../src/* temp_client
rm temp_client/{launch_servers.go,generate_root.go,gobench.go}


cp -r ../src/* temp_server
rm temp_server/{launch_client.go,generate_root.go,gobench.go}