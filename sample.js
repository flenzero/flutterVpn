
//保存缓存文件
const setSettings = (key,setting) => {
    try{
        var basePath = getAppPath()
        const configFile = path.join(basePath, 'core/setting.json')
        const configData = fs.readFileSync(configFile, 'utf-8')
        const data = aseDecode(configData);
        const configJson = JSON.parse(data)
        configJson[key] = setting
        const jsonString = JSON.stringify(configJson)
        const encode = aseEncode(jsonString)
        fs.writeFileSync(configFile, encode, 'utf-8')
        return true
    
    }catch(err){}
    return false;
}

//获取缓存文件
const getSettings = (key) => {
    try{
        var basePath = getAppPath()
        const configFile = path.join(basePath, 'core/setting.json')
        const configData = fs.readFileSync(configFile, 'utf-8')
        const data = aseDecode(configData);
        const configJson = JSON.parse(data)
        if (configJson[key])
        {
          return configJson[key]
        }
        return {}
    
    }catch(err){}
    return {}
}

let sky_port = 55655

//保存缓存文件
const generateSSLocalConfig = (netID, ip,port, method, password) => {
    try{
        var basePath = app.getPath('userData')
        const configFile = path.join(basePath, 'sslocal.conf')
        const configJson = {
            "local_address": "0.0.0.0",
            "local_port": sky_port,//55655,
            "mode":"tcp_and_udp",
            "outbound_bind_interface": netID,
            "locals": [
                {
                    "protocol": "dns",
                    "local_address": "0.0.0.0",
                    "local_port": 53,
                    "mode": "tcp_and_udp",
                    "local_dns_address": "223.5.5.5",
                    "local_dns_port": 53,
                    "remote_dns_address": "99.83.168.226",
                    "remote_dns_port": 18888
                }
            ],
            "server": ip,
            "server_port": port,
            "method": method,
            "password": password
        }
        const jsonString = JSON.stringify(configJson)
        fs.writeFileSync(configFile, jsonString, 'utf-8')
        return configFile
    
    }catch(err){}
    return "";
}


const vpnNetIDExist = () =>{
    return new Promise((resolve,reject)=>{
        // 获取网络接口信息
        const networkInterfaces = os.networkInterfaces();
        if ('skyline-vpn-ethernet' in networkInterfaces)
        {
            resolve()
        }else{
            reject(new Error('未找到相关网卡'))
        }

    })
}

const getRandomInt = (min, max) =>{
    min = Math.ceil(min)
    max = Math.ceil(max)
    return Math.floor(Math.random() * (max - min + 1)) + min
}

const retryOperation = (operation, maxRetries, delay) =>{
    return new Promise((resolve, reject)=>{
        const attempt = () =>{
            operation()
                .then(resolve)
                .catch(err =>{
                    if (maxRetries === 0){
                        reject(err)
                    }else{
                        maxRetries --
                        log.log('未找到网卡，等待重试')
                        setTimeout(attempt, delay)
                    }
                })
        }

        attempt()
    })
}



const getNetIDs = ()=>{
    // 获取网络接口信息
    const networkInterfaces = os.networkInterfaces();

    // 找到处于活动状态的网络接口
    const activeInterfaces = Object.keys(networkInterfaces).reduce((acc, interfaceName) => {
        const interfaces = networkInterfaces[interfaceName]
        const isActive = interfaces.some((iface) => iface.internal === false && iface.address !== '127.0.0.1' && iface.mac !== '00:00:00:00:00:00')
        const interfaceName_toLowerCase = interfaceName.toLowerCase()
        const filterNetIDAry = ['virtual','tap','vpn','tun','meta','vethernet','radmin']
        const isExcluded = filterNetIDAry.some(filter => interfaceName_toLowerCase.includes(filter))
//        const isExcluded = interfaceName_toLowerCase.includes('virtual') || interfaceName_toLowerCase.includes('tap') || interfaceName_toLowerCase.includes('vpn') || interfaceName_toLowerCase.includes('meta') || interfaceName_toLowerCase.includes('tun') || interfaceName_toLowerCase.includes('vethernet') || interfaceName_toLowerCase.includes('radmin')
        if (isActive && !isExcluded) {
          acc.push(interfaceName);
        }
        return acc
    }, [])
    return activeInterfaces
}

const getNetID = async () =>{
    return new Promise((resolve,reject) =>{
        exec('wmic nic where "NetEnabled=TRUE and not Name like \'%Virtual%\' and not Name like \'%tap%\' and not Name like \'%vpn%\' and not Name like \'%meta%\' and not Name like \'%tun%\' and not Name like \'%vEthernet%\'" get NetConnectionID /value', (error, stdout, stderr) => {
            if (error) {
              reject(error)
              return
            }
            const lines = stdout.split('\r\r\n')
            for (let line of lines) {
                const match = line.match(/NetConnectionID=(.*)/)
                if (match && match[1]) {
                    resolve(match[1].trim())
                    return
                }
            }
            reject('NetConnectionID not found')
        })
    })
}

const netshCommand1 = async ()=>{
    return new Promise((resolve,reject) =>{
        exec('netsh interface ip set address skyline-vpn-ethernet static 10.1.88.88 255.255.255.255 10.1.88.1', (error, stdout, stderr) => {
            if (error) {
              reject(error)
            }else
                resolve(stdout)
        })
    })
}
const netshCommand2 = async ()=>{
    return new Promise((resolve,reject) =>{
        exec('netsh interface ip set dnsservers skyline-vpn-ethernet static address=127.0.0.1', (error, stdout, stderr) => {
            if (error) {
              reject(error)
            }else
                resolve(stdout)
        })
    })
}

let waitSslocal1ProcessToExit
let sslocal1Process
const startSslocal1 =async (ip,port,password,method,netId,global) =>{
    log.info(" start sslocal1 process ------>")
    var _path = ""
    if (isDebug) {
        _path = process.cwd()
    } else {
        _path = path.dirname(app.getPath('exe'))
    }
    const childProcess = require('child_process')

    const args = []

    const sslocal_config = generateSSLocalConfig(netId, ip, port, method, password)
    args.push('-c', sslocal_config)

    let acl_config;
    if (global){
        acl_config = path.join(_path,'core/bypass-lan-china.acl')
        args.push('--acl', acl_config)
    }else{
        acl_config = path.join(_path,'core/global.acl')
    }

    log.info("args:" + args)
    try {
        if (vpnStoping)
        {
            return
        }
        let execProcess = path.join(_path,'core/sslocal.exe')
        sslocal1Process = childProcess.spawn(execProcess, args)
        return (waitSslocal1ProcessToExit = new Promise((resolve,reject)=>{
            const onExit = (code, signal)=>{
                if (sslocal1Process){
                    sslocal1Process.removeAllListeners()
                    sslocal1Process = null
                }else{
                    return
                }
                log.log('Sslocal1 exit')

                if (code ===0 || signal === 'SIGTERM'){
                    resolve()
                }else if (code){
                    reject(new Error(`SSLocal1 Process terminated by non-zero exit code:${code}`))
                }else {
                    reject(new Error(`SSLocal1 Process terminated by signal:${signal}`))
                }
                if (connected){
                    startSslocal1()
                }else{//退出时删除掉sslocal启动文件
                    var basePath = app.getPath('userData')
                    const sslocalConfig = path.join(basePath, 'sslocal.conf')
                    fs.access(sslocalConfig, fs.constants.F_OK, (err)=>{
                        if(!err){
                            fs.unlink(sslocalConfig,(e)=>{

                            })
                        }
                    })
                }
            }
            const onStdErr = (data)=>{
                    log.info(`stderr - SSLocal: ${data}`)
            }

            sslocal1Process.stderr.on('data',onStdErr)

            sslocal1Process.on('error',onExit)
            sslocal1Process.on('exit', onExit)
        }))
    } catch (error) {
        log.error(error)
    }    
}



let waitTun2socksProcessToExit
let tun2socksProcess
const startTun2Socks =async (netId) =>{
    log.info(" start tun2socks process ------>")
    var _path = ""
    if (isDebug) {
        _path = process.cwd()
    } else {
        _path = path.dirname(app.getPath('exe'))
    }
    const childProcess = require('child_process')

    const args = []//-device skyline-ethernet -proxy socks5://127.0.0.1:1088 -interface
    args.push('-device','skyline-vpn-ethernet')
    args.push('-proxy',`socks5://127.0.0.1:${sky_port}`)
    args.push('-interface',Buffer.from(netId))
    log.info("args:" + args)
    try {
        if (vpnStoping)
            return
        let execProcess = path.join(_path,'core/tun2socks.exe')
        tun2socksProcess = childProcess.spawn(execProcess, args)
        return (waitTun2socksProcessToExit = new Promise((resolve,reject)=>{
            const onExit = (code, signal)=>{
                if (tun2socksProcess){
                    tun2socksProcess.removeAllListeners()
                    tun2socksProcess = null                    
                }else{
                    return
                }
                log.log('Tun2socks exit')

                if (code ===0 || signal === 'SIGTERM'){
                    resolve()
                }else if (code){
                    reject(new Error(`Tun2Socks Process terminated by non-zero exit code:${code}`))
                }else {
                    reject(new Error(`Tun2Socks Process terminated by signal:${signal}`))
                }
                if (connected){
                    startTun2Socks(vpnConfig.netID)
                    new Promise((resolve1,reject1)=>{
                        setTimeout(async ()=>{
                            retryOperation(vpnNetIDExist, 1, 3000)
                                .then(async ()=>{
                                    log.log('启动netsh命令开始')
                                    await netshCommand1()
                                    await netshCommand2()   
                                    log.log('启动netsh命令完成')
                                    resolve1()                 
                                })
                                .catch((err)=>{
                                    log.error(error)          
                                    reject1(err)
                                })
                        },3000)    
                    }).catch((err)=>{
                        log.error('netsh 失败')
                        vpnStop(0)
                    })            
                    /*
                    new Promise((resolve1,reject1)=>{
                        setTimeout(async ()=>{
                            try {
                                log.log('启动netsh命令开始')
                                await netshCommand1()
                                await netshCommand2()   
                                log.log('启动netsh命令完成')
                                resolve1()                 
                            } catch (error) {
                                log.error(error)          
                                reject1(error)      
                            }    
                        },3000)    
                    })*/          
                }
            }
            const onStdErr = (data)=>{
                    log.info(`stderr - Tun2Socks: ${data}`)
            }

            tun2socksProcess.stderr.on('data',onStdErr)

            tun2socksProcess.on('error',onExit)
            tun2socksProcess.on('exit', onExit)
        }))
    } catch (error) {
        log.error(error)
    }    
}



const stopSsllocal1 = async ()=>{
    if (!sslocal1Process){
        return
    }
    sslocal1Process.kill()
    return waitSslocal1ProcessToExit
}



const stopTun2socks = async ()=>{
    if (!tun2socksProcess){
        return
    }
    tun2socksProcess.kill()
    return waitTun2socksProcessToExit
}


let vpnStoping = false
const dnsPromise = dns.promises
let vpnConfig = {}

const suspendListener = async () =>{
    disconnectVpn()
}
const resumeListener = async () =>{
    if (connected){
        connectVpn(vpnConfig.ip, vpnConfig.port, vpnConfig.uuid, vpnConfig.method, vpnConfig.global)
    }
}

const connectVpn = async (ip, port, uuid, method, global) =>{
    const netIDs = getNetIDs()
    if (netIDs.length<=0){
        throw new Error('取NetID失败')
    }else{
        log.log('启动开始')
        const netID = netIDs[0]
        log.log('NetID:',netID)
        vpnConfig.netID = netID
        sky_port = getRandomInt(5000, 60000)
        startSslocal1(ip,port, uuid, method, netID, global)
        startTun2Socks(netID)
        try {
            await new Promise((resolve,reject)=>{
                setTimeout(async ()=>{
                    retryOperation(vpnNetIDExist, 1, 3000)
                        .then(async ()=>{
                            log.log('启动netsh命令开始')
                            await netshCommand1()
                            await netshCommand2()   
                            log.log('启动netsh命令完成')
                            resolve()                 
                        })
                        .catch((err)=>{
                            log.error(error)          
                            reject(err)
                        })
                },3000)    
            })            
        } catch (error) {
            log.error('netsh 失败')
            vpnStop(0)
        }

        log.log('启动完成')
    }
    return true
}
const disconnectVpn = async ()=>{
    try {
        await stopTun2socks()        
    } catch (error) {
        log.log(error)
    }
    try {
        await stopSsllocal1()        
    } catch (error) {
        log.log(error)
    }
}

const vpnStart =async (tunId, uuid, host, port, method,global) =>{
    log.log("VPN START",host,global)
    if (tun2socksProcess != null || sslocal1Process != null)
    {
        mainWindow.webContents.send('vpnStart',`{"code":1003,"message":"子进程已启动"}`)
        return
    }
    vpnStoping = false
    let ip = host
    let errorMessage = ''
    let errorCode = 0
    try {
        const dnsret = await dnsPromise.lookup(host,{family:4})
        ip = dnsret.address            
    } catch (error) {
        errorCode = 1001
        errorMessage = '解析域名出错'
    }
    if (errorCode == 0){
        vpnConfig = {tunId,ip, uuid, host, port, method,global}
        try {
            connectVpn(ip,port,uuid,method,global)
            connected = true
            if (isWin) {
                powerMonitor.on('suspend', suspendListener.bind(this));
                powerMonitor.on('resume', resumeListener.bind(this));
            }              
        } catch (error) {
            log.error(error)
            errorCode = 1002
            errorMessage = error.message
        }
    }
    mainWindow.webContents.send('vpnStart',`{"code":${errorCode},"message":"${errorMessage}"}`)
    console.log("Start end")
}

const vpnStop = async(global)=>{
    let errorMessage = ''
    let errorCode = 0
    if (vpnStoping){
        return
    }
    vpnStoping = true
    if (isWin) {
        powerMonitor.removeListener('suspend', suspendListener.bind(this));
        powerMonitor.removeListener('resume', resumeListener.bind(this));
    }
    connected = false;
    await disconnectVpn()
    console.log("Stop end")
    mainWindow.webContents.send('vpnStop',`{"code":${errorCode},"message":"${errorMessage}"}`)
    return new Promise((resolve,reject)=>{
        resolve()
    })
}

app.encodefile = async () => {
    var basePath = getAppPath()
    const configFile = path.join(basePath, 'core/setting.json')
    const configData = fs.readFileSync(configFile, 'utf-8')
    const encode = aseEncode(configData)
    fs.writeFileSync(configFile, encode, 'utf-8')
    return true
}

app.decodefile = async () => {
    var basePath = getAppPath()
    const configFile = path.join(basePath, 'core/setting.json')
    const configData = fs.readFileSync(configFile, 'utf-8')
    const encode = aseDecode(configData)
    fs.writeFileSync(configFile, encode, 'utf-8')
    return true
}

app.encodefile1 = async () => {
    var basePath = getAppPath()
    const configFile = path.join(basePath, 'core/url.json')
    const configData = fs.readFileSync(configFile, 'utf-8')

    const encode = aseEncodeForParams(configData,'c5ac11be17b547d8f6b41017f59e4d3b','0123456789abcdef')
    fs.writeFileSync(configFile, encode, 'utf-8')
    return true
}

app.decodefile1 = async () => {
    var basePath = getAppPath()
    const configFile = path.join(basePath, 'core/url.json')
    const configData = fs.readFileSync(configFile, 'utf-8')

    const encode = aseDecodeForParams(configData,'c5ac11be17b547d8f6b41017f59e4d3b','0123456789abcdef')
    fs.writeFileSync(configFile, encode, 'utf-8')
    return true
}

app.log = log
app.isMacOS = isMacOS
app.getSettings = getSettings
app.setSettings = setSettings
app.vpnStart = vpnStart
app.vpnStop = vpnStop


app.test = async () => {
    sslocal1Process.kill()
}