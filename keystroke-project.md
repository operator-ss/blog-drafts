#  TECHNICAL ANALYSIS OF KEYSTROK

22 March, 2024.


## **Table Of Contents**

+	Objective.
+   The Keystrok-project.
+	Basic Static Analysis.
+	Features.
+	Anomalies of the malware.
+	Detection.
+	Tactics, Techniques and Procedure.
+	Indicators of Compromise. 
+	How InfinitY Can Help.




## **Objective**

Recently, as per our stealer malware hunting process, we uncovered a strange Golang malware, along with us another fellow [researcher](https://twitter.com/suyog41/status/1769705553511473563) from the community, also came across this strange sample. The malicious binary focuses on the keylogging aspect, in terms of malicious activity, and then uses a legitimate web service and social media, known as Telegram for exfiltrating the data using a telegram bot. 


## **The Keystrok-project.** 

After, we did receive the sample on our telemetry which is powered by our detection rules completely based on YARA signatures.

![Name-Of-Project](Project-Name.png)

We found out that the sample had been programmed in Golang and the name of the project along with the alias of the developer. 



## **Basic Static Analysis.**



![Project-Name](https://github.com/operator-ss/blog-drafts/assets/161946103/075db6ed-ad07-4a65-a976-82ead86d9bcb)



Using basic PE analysis tools like PE-Studio, we discovered that the binary is a 64-bit executable file.

![strings-basic-static-analysis](https://github.com/operator-ss/blog-drafts/assets/161946103/f805c576-b9d7-46ae-94b4-4ceb1e8832ab)

Then, moving ahead, we figured out that the file is programmed using Golang, one of the modern go-to languages for stealer developers. 





## **Features.**


Let us analyze this malicious sample to determine its workings and capabilities. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/8ad40dc2-0f6a-4080-b053-6e634558fce0)


Once we load the file in IDA-Freeware an analysis tool, we can see that the post-autoanalysis, we have the `main_main` function, which is supposedly the entry point for most Golang-based malware. Then moving ahead it performs some basic routine checks which are completely independent of the malware working. 


![image](https://github.com/operator-ss/blog-drafts/assets/161946103/82af1057-8965-4580-a4de-2bd0e63e8763)

Then, once the routine initialization is done, the code uses `encoding_base64__ptr_Encoding_DecodeString` function to decode a base64 encoded content. 


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

 Then it goes ahead and uses the `GetUpdatesChan` function to get the updates for the channel.  Now, lets move ahead to the keylogging part of the malware. 


 


 











