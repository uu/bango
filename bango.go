//
// Michael Pirogov © 2025 <vbnet.ru@gmail.com>
//

package main

import (
    "log"
    "fmt"
    "github.com/redis/go-redis/v9"
    "runtime"
    "os"
    "context"
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
    log.Printf("Starting %s version", version)

    action, payload := ParseFlags()
    runtime.GOMAXPROCS(4)
    CreateConnection()

    switch action {
    case "publish":
        BangoPublish(config.fail2ban.channel, payload)
    default:
        BangoSubscribe()
    }
}

func CreateConnection() {
    var serverstring = ""
    serverstring = config.redis.server+":"+config.redis.port

    client = redis.NewClient(&redis.Options{
                                        Addr:     serverstring,
                                        Password: config.redis.pass,
                                        Protocol: 2, // RESP2 for compatibility
                                        DB:       int(config.redis.db),})
    pong, err := client.Ping(context.Background()).Result()

    if err == nil {
        log.Println("Connected succesfully and got", pong, "from redis://" + serverstring)
    } else {
        panic(err.Error())
    }
}

func BangoSubscribe() {
    pubsub := client.Subscribe(context.Background(), config.fail2ban.channel)
    defer pubsub.Close()
    var unbanprefix = "unban"

    for {
        msg, err := pubsub.ReceiveMessage(context.Background())
        _ = err
        if err != nil {
            log.Println("Subscription failed")
        }

        log.Println("Received:", msg.Channel, msg.Payload)
        if strings.HasPrefix(msg.Payload, unbanprefix) {
            UnBanIP(strings.TrimPrefix(msg.Payload,unbanprefix))
        } else {
            BanIP(msg.Payload)
        }
    }
}

func BanIP(ip string) {
    if CheckIP(ip) {
        if CheckBanIP(ip) {
            ExecCommand("fail2ban-client", "set", config.fail2ban.jail, "banip", ip)
        }
    }
}

func UnBanIP(ip string) {
    if CheckIP(ip) {
        ExecCommand("fail2ban-client", "set", config.fail2ban.jail, "unbanip", ip)
    }
}

func CheckBanIP(ip string) bool {
    res := ExecCommand("fail2ban-client", "get", config.fail2ban.jail, "banned", ip)
    if res != "0" {
        log.Printf("IP %s already banned", ip)
    }
    return (res == "0") // true if not banned
}

func BangoPublish(channel, payload string) {
    log.Println("Starting publish in '" + channel + "' channel")
	pub := client.Publish(context.Background(), channel, payload)

	if pub.Err() == nil {
		log.Printf("Successfully published '%s'", payload)
	}
}

//
// CONFIG
//

const (
    version = "0.0.5"
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
        return true
    }
}

func ExecCommand(command string, args ...string) string {
    binary, lookErr := exec.LookPath(command)
    if lookErr != nil {
        panic(lookErr)
    }

    if config.global.debug {
        log.Println("Launching:", command, args)
    }

    // actually call
    output, err := exec.Command(binary, args...).CombinedOutput()
    if err != nil {
        log.Fatal(err)
    }

    if err != nil {
        log.Printf("Command finished with error: %v", err)
        log.Printf("Output: %s", output)
    }
    return strings.Trim(fmt.Sprintf("%s", output), "\n")
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
