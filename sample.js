const generateSSLocalConfig = (netID, ip,port, method, password, global) => {
    try{
        var basePath = app.getPath('userData')
        const configFile = path.join(basePath, 'sslocal.conf')
        
        let corePath = '' //core所在目录，windows下c:\aa\bb,要把\转义成\\
        if (isDebug) {
            corePath = process.cwd()
        } else {
            corePath = path.dirname(app.getPath('exe'))
        }            
        corePath = path.join(corePath,'core')
        corePath = corePath.replace(/\\/g, '\\\\')

        let configJson = {}
        if (global){
            configJson = {
                "local_address": "::",
                "local_port": sky_port,//55655,
                "mode":"tcp_and_udp",
                "outbound_bind_addr": netID,
                "locals": [
                    {
                        "protocol": "dns",
                        "local_address": "::",
                        "local_port": 53,
                        "mode": "tcp_and_udp",
                        "local_dns_address": "223.5.5.5",
                        "local_dns_port": 53,
                        "remote_dns_address": "99.83.227.52",
                        "remote_dns_port": 18888
                    },
                    {
                        "protocol": "tun",
                        "tun_interface_name": "skyline-vpn-ethernet",
                        "tun_interface_address": "10.255.0.1/24"
                    }            
                ],
                "server": ip,
                "server_port": port,
                "method": method,
                "password": password
            }    
        }else{
            configJson = {
                "local_address": "::",
                "local_port": sky_port,//55655,
                "mode":"tcp_and_udp",
                "outbound_bind_addr": netID,
                "locals": [
                    {
                        "protocol": "fake-dns",
                        "local_address": "::",
                        "local_port": 53,
                        "fake_dns_ipv4_network": "192.18.0.0/15",
                        "fake_dns_ipv6_network": "ff10::/64",
                        "fake_dns_database_path":corePath,
                        "fake_dns_record_expire_duration": 10
                    },
                    {
                        "protocol": "tun",
                        "tun_interface_name": "skyline-vpn-ethernet",
                        "tun_interface_address": "10.255.0.1/24"
                    }            
                ],
                "server": ip,
                "server_port": port,
                "method": method,
                "password": password
            }
    
        }
        const jsonString = JSON.stringify(configJson)
        fs.writeFileSync(configFile, jsonString, 'utf-8')
        return configFile
    
    }catch(err){}
    return "";
}