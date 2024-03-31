#  TECHNICAL ANALYSIS OF KEYSTROK

22 March, 2024.


## Table Of Contents

+	Objective.
+ The Keystrok-project.
+	Basic Static Analysis.
+	Features.
+	Anomalies of the malware.
+	Detection.
+	Tactics, Techniques and Procedure.
+	Indicators of Compromise. 
+	How InfinitY Can Help.




## Objective

Recently, as per our stealer malware hunting process, we uncovered a strange Golang malware, along with us another fellow [researcher](https://twitter.com/suyog41/status/1769705553511473563) from the community, also came across this strange sample. The malicious binary focuses on the keylogging aspect, in terms of malicious activity, and then uses a legitimate web service and social media, known as Telegram for exfiltrating the data using a telegram bot. 


## The Keystrok-project.


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/18d1bd28-9440-4b0e-9f5c-1dda89d427c9)


After, we did receive the sample on our telemetry which is powered by our detection rules completely based on YARA signatures. We found out that the sample had been programmed in Golang and the name of the project along with the alias of the developer. 


## Basic Static Analysis.



![Project-Name](https://github.com/operator-ss/blog-drafts/assets/161946103/075db6ed-ad07-4a65-a976-82ead86d9bcb)



Using basic PE analysis tools like PE-Studio, we discovered that the binary is a 64-bit executable file.

![strings-basic-static-analysis](https://github.com/operator-ss/blog-drafts/assets/161946103/f805c576-b9d7-46ae-94b4-4ceb1e8832ab)

Then, moving ahead, we figured out that the file is programmed using Golang, one of the modern go-to languages for stealer developers. 





## Features.


Let us analyze this malicious sample to determine its workings and capabilities. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/8ad40dc2-0f6a-4080-b053-6e634558fce0)


Once we load the file in IDA-Freeware an analysis tool, we can see that the post-autoanalysis, we have the `main_main` function, which is supposedly the entry point for most Golang-based malware. Then moving ahead it performs some basic routine checks which are completely independent of the malware working. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/82af1057-8965-4580-a4de-2bd0e63e8763)

Then, once the routine initialization is done, the code uses the `encoding_base64__ptr_Encoding_DecodeString` function to decode a base64 encoded content. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/9900fb0f-df0f-4728-a31b-f6a658137938)


Now, if we look into the memory, we can see that the decoded content is a telegram bot token, which would be used later to exfiltrate stolen data over Telegram.


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/b0d6e648-1850-475d-b32e-51eddad86bc9)

Next, it uses a Golang-oriented function known as `runtime_slicebytetostring` to convert the byte array to a string object. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/e0e5e4f8-9b04-4e43-ac1d-a1f5cfff8d4a)


```go
// NewBotAPIWithClient creates a new BotAPI instance
// and allows you to pass a http.Client.
//
// It requires a token, provided by @BotFather on Telegram and API endpoint.
func NewBotAPIWithClient(token, apiEndpoint string, client HTTPClient) (*BotAPI, error) {
	bot := &BotAPI{
		Token:           token,
		Client:          client,
		Buffer:          100,
		shutdownChannel: make(chan interface{}),

		apiEndpoint: apiEndpoint,
	}

	self, err := bot.GetMe()
	if err != nil {
		return nil, err
	}

	bot.Self = self

	return bot, nil
}
```

Then it goes ahead and uses this code to create a bot instance, which takes the bot token, which we saw above as one of the parameters.


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/6695398e-5ee2-41c6-baa8-3ea3c0146ab5)


```go
func (bot *BotAPI) GetUpdatesChan(config UpdateConfig) UpdatesChannel {
	ch := make(chan Update, bot.Buffer)

	go func() {
		for {
			select {
			case <-bot.shutdownChannel:
				close(ch)
				return
			default:
			}

			updates, err := bot.GetUpdates(config)
			if err != nil {
				log.Println(err)
				log.Println("Failed to get updates, retrying in 3 seconds...")
				time.Sleep(time.Second * 3)

				continue
			}

			for _, update := range updates {
				if update.UpdateID >= config.Offset {
					config.Offset = update.UpdateID + 1
					ch <- update
				}
			}
		}
	}()

	return ch
}
```

 Then it goes ahead and uses the `GetUpdatesChan` function to get the updates for the channel.  Now, let's move ahead to the keylogging part of the malware. 
 

 ![image](https://github.com/operator-ss/blog-drafts/assets/161946103/f47cc87f-d9fe-4057-9f42-94f9525ee007)


Now, here we see that the malware sample uses a Golang-based library known as `kindlyfire` for keylogging purposes. With a little research, it can be found that the `kindlyfire` is an open-source project, basically a keylogger prototype. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/ec9822e0-c236-45e3-8001-200ea7f76cc1)


Here, we can see that there are three functions, out of them, two are specifically performing the key-logging-oriented tasks. Let us check them out one by one.



![image](https://github.com/operator-ss/blog-drafts/assets/161946103/1cff219c-28af-4548-81e6-247505bf92eb)


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/ecbdeb16-5c2d-4c70-950e-acb7fb5f1e77)


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/fa1e5cde-f9cc-4a9c-856e-84bdef144cf3)



The first function, we will have a look into is the `GetKey` function. This function uses [`GetAsyncKeyState`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate) Windows API, overall, this function calls another function `ParseKeycode`. Overall this function is responsible for getting the current key entered by the user. Now, let us move ahead to the next function, ' ParseKeyCode`.


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/91434c09-5452-491d-a2bb-e3fb4b48a41a)


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/f41d6b5d-9d21-4f2c-a676-d1d435c3bf1e)


This function parses the keys and returns the keys in a rune object, which is performed using `DecodeRuneInString`, which will later be exfiltrated. 

Once we finish the keylogging-based functions, let us move ahead to the other interesting functions. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/bc7b1d6a-e9b4-431d-bd55-43d8e7a4dcbe)


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/dd467f60-0cc2-4ab2-8588-feba6171fe75)



Now, we have the last function, known as `sendDocument`. This uses Telegram bot API to send the exfiltrated data that is the keystrokes to the Telegram C2. With this, we are done with the analysis of the features of the keystroke project.  Summing up the features of the project are as follows. 

- Keylogging.
- Telegram C2.
  

![image](https://github.com/operator-ss/blog-drafts/assets/161946103/8d8c6d66-4edd-4a67-8e96-38905369f471)



Upon, some little research, we were able to find out the telegram bot which is being used for exfiltration. 




## Anomalies of the malware.

As per our research & analysis, we believe this malware is a part of the stealer project which is currently in build release, and the author is yet to add more features in the upcoming days. One of the most important anomalies of this malware we believe is the OPSEC failure which is caused by the presence of the PDB path letting researchers know the name of the project and the author. Another notable anomaly is the usage of open-source projects which aids analysts in aiding with the detection part. 



## Detection

We are releasing a public YARA Rule, for the researchers, for tracking this keylogger-oriented project present in the wild.  


```yara
rule keystroke {
    meta:
        author = "SignalZero Threat Research Team"
        description = "YARA rule for detecting malicious keystrok keylogger"
        hash = "9b3df85d5a1abcefa60990439f1478e1b3c6891397fb9ac720e948f31e1864fd"
        date = "2024-03-31"

    strings:
        $asynckeystate = { 48 8B 4C 24 20 48 89 08 48 8B 15 D9 83 29 00 48 89 C3 BF 01 00 00 00 48 89 D0 48 89 F9 E8 D6 A1 E4 FF 66 A9 00 80 }
        $string1 = "C:/Users/salam/Desktop/keystrok/gokb22222"
        $string2 = "/github.com/kindlyfire/go-keylogger"
        $string3 = "telegram-bot-api"
        $opcode = {48 89 D0 48 89 F9 E8 34 9F E4 FF 48 8B 44 24 30 BB 01 00 00 00 48 89 D9 E8 02 A4 E4 FF 66 90 E8 1B 3B E2 FF 89 C3 48 8B 4C 24 60 }

    condition:
        ($opcode and $asynckeystate) or ($string1 or $string2 or $string3)
}
```


## Tactics, Techniques and Procedure.

T1071.001: Command and Control.
T1056.001: Input Capture: Keylogging.
T1567.002: Exfiltration Over Web Service: Exfiltration to Cloud Storage.



## Indicators of Compromise.


SHA-256 : 9b3df85d5a1abcefa60990439f1478e1b3c6891397fb9ac720e948f31e1864fd



## How InfinitY Can Help.

At SignalZero, our dedicated team meticulously monitors the activities of sophisticated threat actors, diligently tracking their movements and dissecting their adversarial infrastructure. Through our highly advanced product, InfinitY, we offer unparalleled defence against malicious implants and the ever-evolving landscape of cyber threats.InfinitY stands at the apex of our defence capabilities, boasting a suite of innovative features meticulously crafted to fortify your organization's security posture. The cutting-edge threat detection algorithms employed by InfinitY are powered by active threat intelligence in the Indian cyber landscape. InfinitY is engineered to provide proactive defence against even the most sophisticated attacks.


When a threat is detected, InfinitY springs into action, swiftly detecting the breach and notifying the stakeholders. Compromised systems can be instantly quarantined to prevent further spread and mitigate potential damage. Our proactive approach ensures a rapid and effective response, safeguarding critical assets and maintaining operational continuity. Furthermore, we are committed to continuously enhancing InfinitY's detection capabilities to stay one step ahead of evolving threats. Through ongoing updates, refinements, and the integration of the latest threat intelligence, InfinitY remains at the forefront of threat detection, identifying and neutralizing adversaries with precision and efficiency. At SignalZero, your security is our utmost priority. With InfinitY as your trusted ally, you can navigate the ever-changing threat landscape with confidence. Rest assured that you're equipped with the most advanced tools and technologies to defend against emerging threats and protect your organization's interests effectively.






 


 


 











