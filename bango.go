//
// Michael Pirogov © 2014 <vbnet.ru@gmail.com>
//

package main

import (
    "log"
    "gopkg.in/redis.v2"
    "runtime"
    "os"
    "strings"
    "os/exec"
    "github.com/Unknwon/goconfig"
    "net"
)

var client *redis.Client

func init() {
    LoadBangoConfig("/etc/bango.ini")
}

func main() {
    action, payload := ParseFlags()
    runtime.GOMAXPROCS(4)
    CreateConnection()

    switch action {
    case "publish":
        BangoPublish("fail2ban", payload)
    default:
        BangoSubscribe()
    }
}

func CreateConnection() {
    var serverstring = ""
    serverstring = config.redis.server+":"+config.redis.port

    client = redis.NewTCPClient(&redis.Options{
                                        Addr:     serverstring,
                                        Password: config.redis.pass,
                                        DB:       int64(config.redis.db),})

    pong, err := client.Ping().Result()

    if err == nil {
        log.Println("Connected succesfully and got", pong, "from redis://" + serverstring)
    } else {
        panic(err.Error())
    }
}

func BangoSubscribe() {
    pubsub := client.PubSub()
    defer pubsub.Close()
    var unbanprefix = "unban"

    err := pubsub.Subscribe("fail2ban")
    _ = err

    for {
        msg, err := pubsub.Receive()
        _ = err
        if err != nil {
            log.Println("Subscription failed")
        }

        switch subscr := msg.(type) {
        case *redis.Subscription:
            log.Println("Subscribed sucessfully to 'fail2ban' channel")
        case *redis.Message:
            log.Println("Received:", subscr.Channel, subscr.Payload)
            if strings.HasPrefix(subscr.Payload, unbanprefix) {
                UnBanIP(strings.TrimPrefix(subscr.Payload,unbanprefix))
            } else {
                BanIP(subscr.Payload)
            }
        default:
            panic("ERROR: Something went wrong: " + err.Error())
        }
    }

}

func BanIP(ip string) {
    if CheckIP(ip) {
        ExecCommand("fail2ban-client", "set", config.fail2ban.jail, "banip", ip)
    }
}

func UnBanIP(ip string) {
    if CheckIP(ip) {
        ExecCommand("fail2ban-client", "set", config.fail2ban.jail, "unbanip", ip)
    }
}




func BangoPublish(channel, payload string) {
    log.Println("Starting publish in 'fail2ban' channel")
	pubsub := client.PubSub()
	defer pubsub.Close()
	pub := client.Publish(channel, payload)

	if pub.Err() == nil {
		log.Printf("Successfully published '%s'", payload)
	}
}

//
// CONFIG
//

const (
    version = "0.0.3"
)

// Packaged all Server settings
type Config struct {
    redis    Redis
    global   Global
    fail2ban Fail2ban
}

type Redis struct {
    server string
    port   string
    db     int
    pass   string
}

type Global struct {
    debug   bool
    logFile string
}

type Fail2ban struct {
    channel string
    jail    string
    useF2C  bool
}

// Define a global config varible
var config Config

func LoadBangoConfig(fileName string) {
    var err error
    _, err = os.Stat(fileName)

    if err != nil {
        if os.IsNotExist(err) {
            panic("Configuration file does not exists: " + err.Error())
        } else {
            panic("Something wrong with configuration file: " + err.Error())
        }
    }

    var cfg *goconfig.ConfigFile
    cfg, err = goconfig.LoadConfigFile(fileName)
    if err != nil {
        panic("Fail to load configuration file: " + err.Error())
    }
    // Parse the global section
    config.global.debug = cfg.MustBool("global", "debug", false)

    // Parse the redis section
    config.redis.server = cfg.MustValue("redis", "server", "localhost")
    config.redis.port = cfg.MustValue("redis", "port", "6379")
    config.redis.db = cfg.MustInt("redis", "db", 0)
    config.redis.pass = cfg.MustValue("redis", "pass", "")

    // Parse the fail2ban section
    config.fail2ban.channel = cfg.MustValue("fail2ban", "channel", "fail2ban")
    config.fail2ban.jail = cfg.MustValue("fail2ban", "jail", "fail2ban-recidive")
    config.fail2ban.useF2C = cfg.MustBool("fail2ban", "usef2bclient", true)
}

//
// UTILS
//

func CheckIP(checkip string) bool {
    trial := net.ParseIP(checkip)
    if trial.To4() == nil {
        log.Printf("ERROR: '%v' is not an IPv4 address. Doing nothing.\n", checkip)
        return false
    } else {
        //		s := trial.To4()
        //		log.Println(reflect.TypeOf(s))
        return true
    }
}

func ExecCommand(command string, args ...string) {
    binary, lookErr := exec.LookPath(command)
    if lookErr != nil {
        panic(lookErr)
    }

    log.Println("Launching:", command, args)

    // actually call
    cmd := exec.Command(binary, args...)
    err := cmd.Start()
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Waiting for command to finish...")
    err = cmd.Wait()
    if err != nil {
        log.Printf("Command finished with error: %v", err)
    }
    log.Printf("done")
}

func ParseFlags() (string, string) {
    var action, payload string = "", ""
    if len(os.Args) > 2 {
        // action: subscribe, publish
        // default: subscribe
        action = os.Args[1]
        // subaction and ip address to ban
        // default: ""
        payload = os.Args[2]
    }
    return action, payload
}
