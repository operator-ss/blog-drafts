#  TECHNICAL ANALYSIS OF KEYSTROK

22 March, 2024.


## **Table Of Contents**

+	Objective.
+   The Keystrok-project.
+	Basic Static Analysis.
+	Features.
	- 		Exfiltration.
	-   	Infrastructure Analysis.
+	Anomalies of the malware.
+	Detection.
+	Tactics, Techniques and Procedure.
+	Indicators of Compromise. 
+	How InfinitY Can Help.




## **Objective**

Recently, as per our stealer malware hunting process, we uncovered a strange Golang malware, along with us another fellow [researcher](https://twitter.com/suyog41/status/1769705553511473563) from the community, also came across this strange sample. The malicious binary focuses on keylogging aspect, in terms of malicious activity, and then uses a legitimate web-service and social media, known as Telegram for exfiltrating the data using a telegram bot. 


## **The Keystrok-project.** 

After, we did receive the sample on our telemetry which is powered by our detection rules completely based on YARA signatures.

![Name-Of-Project](Project-Name.png)

We found out that the sample had been programmed in Golang and the name of the project along with the alias of the developer. 



## **Basic Static Analysis.**



![Project-Name](https://github.com/operator-ss/blog-drafts/assets/161946103/075db6ed-ad07-4a65-a976-82ead86d9bcb)



Upon using basic PE analysis tools like PE-Studio, we figured out that the binary is a 64-bit executable file.

![strings-basic-static-analysis](https://github.com/operator-ss/blog-drafts/assets/161946103/f805c576-b9d7-46ae-94b4-4ceb1e8832ab)

Then, moving ahead, we figured out that the file is programmed using Golang, one of the modern go-to languages for stealer developers. 





## **Features.**


Now, let us analyze this malicious sample, to figure out the workings and capabilities.









