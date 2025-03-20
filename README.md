# Project - B cyber secuity AI based Threat intelligence tool
I created this project based on VirusTotal, a Telegram alert system, and a Squid-based proxy. This project's purpose is to protect  from internet cyber attacks such as phishing, social engineering, and web-based malware sites on the end user devices. 
Live Stream Prdefied based AI.
This script can run as service file.

#Live stream AI and Telegram Alert 
You can copy the service file  and paste to /etc/systemd/system/project_b.service
![image](https://github.com/user-attachments/assets/6d367a2d-ea26-45ed-93a2-c32e4d30daa2)

Live stream AI configuration project 
Add VirusTotal and Telegram Bot Token 
![image](https://github.com/user-attachments/assets/69a7f7cf-2d71-41b3-9655-1033f475e7d4)

Add Live stream file and check_list
Read Log is squid proxy read file.
Check List is history domain file after checked with virus total.
![image](https://github.com/user-attachments/assets/0830db03-b85b-47f8-87ca-472008e03f8c)

Also need add check_list method
Block method file path  is squid block file path.
![image](https://github.com/user-attachments/assets/77987bf4-068c-429b-b07b-e5562da7afe1)

Change Ml data is used for history ai project.
It get and update automathically data from VirusTotal checked domain  and store as json format to train AI.
![image](https://github.com/user-attachments/assets/38052d73-8019-4f4d-a258-d3dae4c2cb99)

Finally SOC Team get the message,if the user clicked or visited the malicious websistes.
![image](https://github.com/user-attachments/assets/05f55200-d2dd-41f4-8626-c5db9a9879a2)

#History AI
Sometime live ai can missed to scan the some domain.So, SOC member can run the script with history log file and It is output with excel output.
Configure the below image.
![image](https://github.com/user-attachments/assets/aa2acfc0-abce-41a6-b94d-d2a16c7f6b54)

##Output excel
It depends on the AI data.
![image](https://github.com/user-attachments/assets/25cb90b8-b0f1-4273-a7e7-c3e33b6563f9)

Support 
BTC: bc1q3hrceg98v97p0l8rw2z9n7lu0wgcyes88jtt4d
LTC: ltc1qxw5mflrvn8qrnq0hvl847eunr4he29ma7nuxj2



