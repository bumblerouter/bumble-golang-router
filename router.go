package router

import (
	"bumbleserver.org/common/envelope"
	"bumbleserver.org/common/key"
	"bumbleserver.org/common/message"
	"bumbleserver.org/common/peer"
	"bumbleserver.org/common/session"
	"bumbleserver.org/common/util"
	"code.google.com/p/go.net/websocket"
	"crypto/rsa"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"syscall"
	"time"
)

var myself *peer.Peer
var myprikey *rsa.PrivateKey

type Config struct {
	NetBind               string
	Name                  string
	PrivateKey            *rsa.PrivateKey
	SessionTimeout        int
	AuthenticationTimeout int
	KeyFile               string // filename of key (only required if wanting TLS)
	CertFile              string // filename of cert (only required if wanting TLS)
	StatHatKey            string // if using StatHat, this is the EZ key (we might want to remove StatHat from this library)
}

var authenticationTimeout int = 30 // defaults to 30 seconds

func RouterStart(config Config) {
	myself = peer.NewFromString(config.Name)

	if config.SessionTimeout > 0 {
		if config.SessionTimeout < 10 {
			config.SessionTimeout = 10
		}
		session.Config(config.SessionTimeout)
	}

	if config.AuthenticationTimeout > 0 {
		if config.AuthenticationTimeout < 10 {
			config.AuthenticationTimeout = 10
		}
		authenticationTimeout = config.AuthenticationTimeout
	}

	myprikey = config.PrivateKey
	if myprikey == nil {
		fmt.Println("Unable to parse your private key, it doesn't exist (make one if so), or some other related problem happened.")
		os.Exit(1)
	}

	if myself.PublicKey() == nil {
		publicKeyURL, err := myself.PublicKeyURL()
		if err != nil {
			fmt.Printf("Unable to locate your public key in the public key store, likely because of this error: %s\n\n", err)
		} else {
			fmt.Printf("Unable to locate your public key in the public key store.\n\nI expected to find the following data stored at %s\n\n%s\n", publicKeyURL, key.PublicKeyToPEM(myprikey.PublicKey))
		}
		os.Exit(1)
	}

	pubkey := myself.PublicKey()
	if pubkey.N.Cmp(myprikey.PublicKey.N) != 0 {
		publicKeyURL, _ := myself.PublicKeyURL()
		fmt.Printf("The global public key store has a public key that doesn't match my own public key stored locally.\n\nI expected to find the following data stored at %s\n\n%s\n", publicKeyURL, key.PublicKeyToPEM(myprikey.PublicKey))
		os.Exit(1)
	}

	util.StatHatSetKey(config.StatHatKey)

	http.Handle("/", http.FileServer(http.Dir("www")))            // FIXME: we probably don't want to hardcode this here (or maybe removed altogether)
	http.Handle("/bumble-client", websocket.Handler(PeerHandler)) // This path is currently defined in the spec, so it should be hardcoded.
	var err error
	if config.KeyFile != "" && config.CertFile != "" {
		err = http.ListenAndServeTLS(config.NetBind, config.CertFile, config.KeyFile, nil)
	} else {
		err = http.ListenAndServe(config.NetBind, nil)
	}
	if err != nil {
		fmt.Printf("L&S: %s\n", err.Error())
		os.Exit(1)
	}
}

var countRoutedMessages = 0
var countRoutedMessagesChan = make(chan bool, 1)
var countRoutedMessagesMax = 5000
var countRoutedMessagesMaxInterval = time.Duration(30e9)
var countRoutedMessagesMaxTime = time.Now().Add(countRoutedMessagesMaxInterval)

func PeerHandler(ws *websocket.Conn) {
	// fmt.Println("PH ENTRY")
	// defer fmt.Println("PH EXIT")
	defer ws.Close()
	util.StatHatCount("Bumble Router Connected Client", 1)
	defer util.StatHatCount("Bumble Router Disconnected Client", 1)
	nonce := ""
	{ // GREETING
		msg := message.NewGeneric(message.CODE_AUTHENTICATE)
		msg.SetInfo("Please authenticate.")
		sig, err := OriginateMessage(ws, msg)
		nonce = sig
		if err != nil {
			fmt.Printf("UACE-ORIGINATEMESSAGE-ERROR: %s\n", err)
			delayedReturn()
			return
		}
		util.StatHatCount("Bumble Router Authentication Request", 1)
	}
	incoming := make(chan *envelope.Envelope)
	disconnected := make(chan bool)
	go PeerEnvelopeReceiver(ws, incoming, disconnected)
	authTimer := time.NewTimer(time.Duration(int64(authenticationTimeout) * 1e9))
	p := new(peer.Peer)
	for {
		// fmt.Println("LOOP")
		select {
		case <-authTimer.C: // UNAUTHENTICATED CONNECTION EXPIRED!
			msg := message.NewGeneric(message.CODE_GENERICERROR)
			msg.SetError("Authentication timeout.")
			_, err := OriginateMessage(ws, msg)
			if err != nil {
				fmt.Printf("UACE-ORIGINATEMESSAGE-ERROR: %s\n", err)
			}
			util.StatHatCount("Bumble Router Authentication Timeout", 1)
			delayedReturn()
			return
		case <-disconnected:
			// fmt.Printf("ROUTER-PEER-DISCONNECTION: %s\n", p)
			session.DisconnectSession(p)
			return
		case env := <-incoming:
			// fmt.Printf("RECEIVED ENVELOPE: %s\n", env)
			if env.GetFrom() == nil { // all envelopes have a sender
				msg := message.NewGeneric(message.CODE_GENERICERROR)
				msg.SetError("'From' field missing or malformed.")
				_, err := OriginateMessage(ws, msg)
				if err != nil {
					fmt.Printf("NAME-ME-ORIGINATEMESSAGE-ERROR: %s\n", err)
				}
				util.StatHatCount("Bumble Router Missing FROM", 1)
				delayedReturn()
				return
			}

			if env.GetTo() != nil && env.GetTo().String() == myself.String() { // is this directed at me?
				err := key.VerifyBytesFromString(env.GetFrom().PublicKey(), []byte(env.GetMessageRaw()), env.GetSignature())
				if err != nil {
					fmt.Printf("DIRECT-RECEIVED-MESSAGE-VERIFICATION-ERROR: %s\n", err)
					util.StatHatCount("Bumble Router Env Failed Sig Verify", 1)
					delayedReturn()
					return
				}

				m := env.GetMessage(myprikey)

				messageHeader, err := message.HeaderParse(m)
				if err != nil {
					fmt.Printf("DIRECT-RECEIVED-MESSAGEHEADER-PARSE-ERROR: %s\n", err)
					util.StatHatCount("Bumble Router Env Failed Header Parse", 1)
					delayedReturn()
					return
				}

				if messageHeader.GetFrom() == nil || env.GetFrom() == nil || messageHeader.GetFrom().String() != env.GetFrom().String() {
					// envelope from field doesn't match the message, do something? FIXME
					fmt.Printf("DIRECT-RECEIVED-MISSINGORINVALIDFROM-ERROR: %s\n", messageHeader)
					util.StatHatCount("Bumble Router Env Invalid FROM", 1)
					delayedReturn()
					return
				}

				if !p.Valid() { // peer isn't authenticated yet
					switch {
					case messageHeader.GetCode() == message.CODE_AUTHENTICATION:
						auth, err := message.GenericParse(m)
						if err != nil {
							fmt.Printf("DIRECT-RECEIVED-MESSAGEGENERIC-PARSE-ERROR: %s\n", err)
							util.StatHatCount("Bumble Router Generic Parse Error in Auth", 1)
							delayedReturn()
							return
						}
						// fmt.Printf("MSGTYPE_AUTHENTICATION: %v\n", auth)
						if nonce == "" {
							// this should not be possible
							fmt.Println("**** THIS SHOULD NOT BE POSSIBLE **** (MSGTYPE_AUTHENTICATION)")
							util.StatHatCount("Bumble Router Auth Missing Internal Nonce", 1)
							delayedReturn()
							return
						}
						if auth.GetTo().String() != myself.String() {
							// it wasn't directed at me
							msg := message.NewGeneric(message.CODE_GENERICERROR)
							msg.SetError("Incorrect destination supplied for authentication purpose.")
							util.StatHatCount("Bumble Router Auth TO Bad", 1)
							_, err := OriginateMessage(ws, msg)
							if err != nil {
								fmt.Printf("CHALRESP-BADTO-ERROR: %s\n", err)
							}
							delayedReturn()
							return
						}
						if auth.GetInfo() != nonce {
							// the nonce didn't match
							msg := message.NewGeneric(message.CODE_GENERICERROR)
							msg.SetError("Incorrect nonce supplied.")
							util.StatHatCount("Bumble Router Nonce Invalid", 1)
							_, err := OriginateMessage(ws, msg)
							if err != nil {
								fmt.Printf("CHALRESP-BADNONCE-ERROR: %s\n", err)
							}
							delayedReturn()
							return
						}
						{ // SUCCESSFUL AUTHENTICATION
							p = env.GetFrom()
							if session.NewSession(p, ws) == nil {
								// session is nil which means that there is a session with this name already in use. FIXME: unclear error state
								fmt.Println("NEWSESSION-COLLISION")
								util.StatHatCount("Bumble Router Session Collision", 1)
								msg := message.NewGeneric(message.CODE_AUTHENTICATIONRESULT)
								msg.SetSuccess(false)
								msg.SetInfo("Successful authentication, but failed.")
								msg.SetError("Session with this name already in use.")
								_, err := OriginateMessage(ws, msg)
								if err != nil {
									fmt.Printf("NEWSESSION-COLLISION-ERROR: %s\n", err)
								}
								delayedReturn()
								return
							} else {
								util.StatHatCount("Bumble Router Auth Success", 1)
								msg := message.NewGeneric(message.CODE_AUTHENTICATIONRESULT)
								msg.SetTo(p)
								msg.SetInfo("Successful authentication.")
								msg.SetSuccess(true)
								sig, err := OriginateMessage(ws, msg)
								nonce = sig
								if err != nil {
									fmt.Printf("UACE-ORIGINATEMESSAGE-ERROR: %s\n", err)
									delayedReturn()
									return
								}
								authTimer.Stop()
							}
						}
					case messageHeader.GetType() == message.TYPE_GENERIC:
						gen, err := message.GenericParse(m)
						if err != nil {
							fmt.Printf("DIRECT-RECEIVED-MESSAGEGENERIC-PARSE-ERROR: %s\n", err)
							util.StatHatCount("Bumble Router Unauth Generic Parse Error", 1)
							delayedReturn()
							return
						}
						fmt.Printf("MSGTYPE_GENERIC: %v\n", gen)
						delayedReturn()
						return
					default:
						fmt.Printf("MSGTYPE_???: %v\n", messageHeader.GetType())
						util.StatHatCount("Bumble Router Unauth Recvd Unk MSGTYPE", 1)
						delayedReturn()
						return
					}
				} else { // peer is authenticated and it is for me
					fmt.Printf("THIS PEER WANTS ME TO READ AN ENVELOPE: %s\n", p)
					util.StatHatCount("Bumble Router Recvd Envelope", 1)
				}
			} else if p.Valid() { // peer is authenticated and it is NOT for me
				session.PassEnvelope(env.GetTo(), env) // we're ignoring errors for privacy reasons
				countRoutedMessagesChan <- true
				countRoutedMessages++
				if time.Now().After(countRoutedMessagesMaxTime) || countRoutedMessages >= countRoutedMessagesMax {
					util.StatHatCount("Bumble Router Routed Messages", float32(countRoutedMessages))
					countRoutedMessages = 0
					countRoutedMessagesMaxTime = time.Now().Add(countRoutedMessagesMaxInterval)
				}
				<-countRoutedMessagesChan
			}
		}
	}
}

func delayedReturn() {
	<-time.NewTimer(time.Duration(rand.Int63n(7e9) + 1e9)).C // sleep rand(1,8) secs before disconnect
}

var countOriginateMessages = 0
var countOriginateMessagesChan = make(chan bool, 1)
var countOriginateMessagesMax = 5000
var countOriginateMessagesMaxInterval = time.Duration(30e9)
var countOriginateMessagesMaxTime = time.Now().Add(countOriginateMessagesMaxInterval)

func OriginateMessage(ws *websocket.Conn, msg message.Message) (signature string, err error) {
	msg.SetFrom(myself)
	env, err := envelope.Package(msg, myprikey)
	if err != nil {
		fmt.Printf("ORIGINATEMESSAGE-PACKAGE ERROR: %s\n", err.Error())
		util.StatHatCount("Bumble Router Originate Package Error", 1)
		return
	}
	signature = env.GetSignature()
	err = websocket.JSON.Send(ws, env)
	if err != nil {
		fmt.Printf("ORIGINATEMESSAGE-JSON-SEND ERROR: %s\n", err.Error())
		util.StatHatCount("Bumble Router Originate JSON Send Error", 1)
		return
	}
	countOriginateMessagesChan <- true
	countOriginateMessages++
	if time.Now().After(countOriginateMessagesMaxTime) || countOriginateMessages >= countOriginateMessagesMax {
		util.StatHatCount("Bumble Router Originated Messages", float32(countOriginateMessages))
		countOriginateMessages = 0
		countOriginateMessagesMaxTime = time.Now().Add(countOriginateMessagesMaxInterval)
	}
	<-countOriginateMessagesChan
	return
}

func PeerEnvelopeReceiver(ws *websocket.Conn, incoming chan *envelope.Envelope, disconnected chan bool) {
	// fmt.Println("PER ENTRY")
	// defer fmt.Println("PER EXIT")
	for {
		var env envelope.Envelope
		err := websocket.JSON.Receive(ws, &env)
		if err == nil {
			fmt.Println("[ENVELOPERECEIVED]\t", env)
			incoming <- &env
			continue
		}
		if err == io.EOF || err == syscall.EINVAL || err == syscall.ECONNRESET { // peer disconnected (FIXME: want to get proper test for "read tcp ... use of closed network connection" error)
			disconnected <- true
			break
		}
		if err != nil {
			fmt.Printf("PER ERR: [[[ WARNING: UNHANDLED ERROR ]]] %v\n", err)
			util.StatHatCount("Bumble Router PER Unhandled Error", 1)
			disconnected <- true
			break
		}
	}
}
