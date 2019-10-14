/*ESP-RFID-Tool NodeMCU*/

/*
 * Original Code by
 * 
 * ESP-RFID-Tool
 * by Corey Harding of www.Exploit.Agency / www.LegacySecurityGroup.com
 * ESP-RFID-Tool Software is distributed under the MIT License. The license and copyright notice can not be removed and must be distributed alongside all future copies of the software.
 * MIT License
    
    Copyright (c) [2018] [Corey Harding]
    
    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#include "HelpText.h"
#include "License.h"
#include "version.h"
#include "strrev.h"
#include "aba2str.h"
#include "data_convert.h"
#include <ESP8266WiFi.h>
#include <WiFiClient.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266httpUpdate.h>
#include <ESP8266HTTPUpdateServer.h>
#include <ESP8266mDNS.h>
#include <FS.h>
#include <ArduinoJson.h> // ArduinoJson library 5.11.0 by Benoit Blanchon https://github.com/bblanchon/ArduinoJson
#include <ESP8266FtpServer.h> // https://github.com/exploitagency/esp8266FTPServer/tree/feature/bbx10_speedup
#include <DNSServer.h>


#define DATA0 14
#define DATA1 12

//#define LED_BUILTIN 2
#define RESTORE_DEFAULTS_PIN 4 //GPIO 4
int jumperState = 0; //For restoring default settings
#include "WiegandNG.h" //https://github.com/jpliew/Wiegand-NG-Multi-Bit-Wiegand-Library-for-Arduino //Included in this project, no need to import

// Port for web server
ESP8266WebServer server(80);
ESP8266WebServer httpServer(1337);
ESP8266HTTPUpdateServer httpUpdater;
FtpServer ftpSrv;
const byte DNS_PORT = 53;
DNSServer dnsServer;

HTTPClient http;

const char* update_path = "/update";
int accesspointmode;
char ssid[32];
char password[64];
int channel;
int hidden;
char local_IPstr[16];
char gatewaystr[16];
char subnetstr[16];
char update_username[32];
char update_password[64];
char ftp_username[32];
char ftp_password[64];
int ftpenabled;
int ledenabled;
char logname[31];
unsigned int bufferlength;
unsigned int rxpacketgap;
int txdelayus;
int txdelayms;
int safemode;

int dos=0;
int TXstatus=0;
String experimentalStatus;
String pinHTML;

#include "pinSEND.h"

String dataCONVERSION="";

WiegandNG wg;


void LogWiegand(WiegandNG &tempwg) {
  Serial.println("Hit point x");
  volatile unsigned char *buffer=tempwg.getRawData();
  unsigned int bufferSize = tempwg.getBufferSize();
  unsigned int countedBits = tempwg.getBitCounted();

  unsigned int countedBytes = (countedBits/8);
  if ((countedBits % 8)>0) countedBytes++;
  //unsigned int bitsUsed = countedBytes * 8;

  bool binChunk2exists=false;
  volatile unsigned long cardChunk1 = 0;
  volatile unsigned long cardChunk2 = 0;
  volatile unsigned long binChunk2 = 0;
  volatile unsigned long binChunk1 = 0;
  String binChunk3="";
  bool unknown=false;
  binChunk2exists=false;
  int binChunk2len=0;
  int j=0;
  
  
  for (unsigned int i=bufferSize-countedBytes; i< bufferSize;i++) {
    unsigned char bufByte=buffer[i];
    for(int x=0; x<8;x++) {
      if ( (((bufferSize-i) *8)-x) <= countedBits) {
        j++;
        if((bufByte & 0x80)) {  //write 1
          if(j<23) {
            binChunk1 = binChunk1 << 1;
            binChunk1 |= 1;
          }
          else if(j<=52) {
            binChunk2exists=true;
            binChunk2len++;
            binChunk2 = binChunk2 << 1;
            binChunk2 |= 1;
          }
          else if(j>52){
            binChunk3=binChunk3+"1";
          }
        }
        else {  //write 0
          if(j<23) {
            binChunk1 = binChunk1 << 1;
          }
          else if(j<=52){
            binChunk2exists=true;
            binChunk2len++;
            binChunk2 = binChunk2 << 1;
          }
          else if(j>52){
            binChunk3=binChunk3+"0";
          }
        }
      }
      bufByte<<=1;
    }
  }
  j=0;

  switch (countedBits) {  //Add the preamble to known cards
    case 26:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 2){
          bitWrite(cardChunk1, i, 1); // Write preamble 1's to the 13th and 2nd bits
        }
        else if(i > 2) {
          bitWrite(cardChunk1, i, 0); // Write preamble 0's to all other bits above 1
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 20)); // Write remaining bits to cardChunk1 from binChunk1
        }
        if(i < 20) {
          bitWrite(cardChunk2, i + 4, bitRead(binChunk1, i)); // Write the remaining bits of binChunk1 to cardChunk2
        }
        if(i < 4) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i)); // Write the remaining bit of cardChunk2 with binChunk2 bits
        }
      }
      break;
    case 27:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 3){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 3) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 19));
        }
        if(i < 19) {
          bitWrite(cardChunk2, i + 5, bitRead(binChunk1, i));
        }
        if(i < 5) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 28:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 4){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 4) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 18));
        }
        if(i < 18) {
          bitWrite(cardChunk2, i + 6, bitRead(binChunk1, i));
        }
        if(i < 6) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 29:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 5){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 5) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 17));
        }
        if(i < 17) {
          bitWrite(cardChunk2, i + 7, bitRead(binChunk1, i));
        }
        if(i < 7) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 30:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 6){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 6) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 16));
        }
        if(i < 16) {
          bitWrite(cardChunk2, i + 8, bitRead(binChunk1, i));
        }
        if(i < 8) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 31:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 7){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 7) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 15));
        }
        if(i < 15) {
          bitWrite(cardChunk2, i + 9, bitRead(binChunk1, i));
        }
        if(i < 9) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 32:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 8){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 8) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 14));
        }
        if(i < 14) {
          bitWrite(cardChunk2, i + 10, bitRead(binChunk1, i));
        }
        if(i < 10) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 33:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 9){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 9) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 13));
        }
        if(i < 13) {
          bitWrite(cardChunk2, i + 11, bitRead(binChunk1, i));
        }
        if(i < 11) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 34:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 10){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 10) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 12));
        }
        if(i < 12) {
          bitWrite(cardChunk2, i + 12, bitRead(binChunk1, i));
        }
        if(i < 12) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 35:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 11){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 11) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 11));
        }
        if(i < 11) {
          bitWrite(cardChunk2, i + 13, bitRead(binChunk1, i));
        }
        if(i < 13) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 36:
      for(int i = 19; i >= 0; i--) {
        if(i == 13 || i == 12){
          bitWrite(cardChunk1, i, 1);
        }
        else if(i > 12) {
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 10));
        }
        if(i < 10) {
          bitWrite(cardChunk2, i + 14, bitRead(binChunk1, i));
        }
        if(i < 14) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    case 37:
      for(int i = 19; i >= 0; i--) {
        if(i == 13){
          bitWrite(cardChunk1, i, 0);
        }
        else {
          bitWrite(cardChunk1, i, bitRead(binChunk1, i + 9));
        }
        if(i < 9) {
          bitWrite(cardChunk2, i + 15, bitRead(binChunk1, i));
        }
        if(i < 15) {
          bitWrite(cardChunk2, i, bitRead(binChunk2, i));
        }
      }
      break;
    default:  //unknown card
      unknown=true;
      //String binChunk3 is like cardChunk0
      cardChunk1=binChunk2;
      cardChunk2=binChunk1;
      break;
  }

  File f = SPIFFS.open("/"+String(logname), "a"); //Open the log in append mode to store capture
  int preambleLen;
  if (unknown==true && countedBits!=4 && countedBits!=8 && countedBits!=248) {
    f.print(F("Unknown "));
    preambleLen=0;
  }
  else {
    preambleLen=(44-countedBits);
  }
  
  f.print(String()+countedBits+F(" bit card,"));

  if (countedBits==4||countedBits==8) {
    f.print(F("Possible keypad entry,"));
  }

  if (countedBits==248) {
    f.print(F("possible magstripe card,"));
  }
  String magstripe="";

  if (unknown!=true) {
    f.print(String()+preambleLen+F(" bit preamble,"));
  }
  
  f.print(F("Binary:"));

  //f.print(" ");  //debug line
  if (binChunk2exists==true && unknown!=true) {
    for(int i = (((countedBits+preambleLen)-countedBits)+(countedBits-24)); i--;) {
      if (i==((((countedBits+preambleLen)-countedBits)+(countedBits-24))-preambleLen-1) && unknown!=true) {
        f.print(" ");
      }
      f.print(bitRead(cardChunk1, i));
      if(i == 0){
        break;
      }
    }
  }
  
  if ((countedBits>=24) && unknown!=true) {
    for(int i = 24; i--;) {
      f.print(bitRead(cardChunk2, i));
      if(i == 0){
        break;
      }
    }
  }
  else if ((countedBits>=23) && unknown==true) {
    int i;
    if (countedBits>=52) {
      i=22;
    }
    else {
      i =(countedBits-binChunk2len);
    }
    for(i; i--;) {
      f.print(bitRead(binChunk1, i));
      if (countedBits==248) {
        magstripe+=bitRead(binChunk1, i);
      }
      if(i == 0){
        break;
      }
    }
  }
  else {
    for(int i = countedBits; i--;) {
      f.print(bitRead(binChunk1, i));
      if(i == 0){
        break;
      }
    }
  }

  if (binChunk2exists==true && unknown==true) {
    int i;
    if (countedBits>=52) {
      i=30;
    }
    else {
      i=(binChunk2len);
    }
    for(i; i--;) {
      f.print(bitRead(binChunk2, i));
      if (countedBits==248) {
        magstripe+=bitRead(binChunk2, i);
      }
      if(i == 0){
        break;
      }
    }
  }

  if (countedBits>52) {
    f.print(binChunk3);
    if (countedBits==248) {
        magstripe+=binChunk3;
    }
  }

  if (countedBits<=52 && unknown!=true) {
    f.print(",HEX:");
    if (binChunk2exists==true) {
      f.print(cardChunk1, HEX);
    }
    //f.print(" "); //debug line
    f.println(cardChunk2, HEX);
  }
  else if (countedBits==4||countedBits==8) {
    f.print(",Keypad Code:");
    if (binChunk1 == 0B0000||binChunk1 == 0b11110000) {
      f.print("0");
    }
    else if (binChunk1 == 0B0001||binChunk1 == 0b11100001) {
      f.print("1");
    }
    else if (binChunk1 == 0B0010||binChunk1 == 0b11010010) {
      f.print("2");
    }
    else if (binChunk1 == 0B0011||binChunk1 == 0b11000011) {
      f.print("3");
    }
    else if (binChunk1 == 0B0100||binChunk1 == 0b10110100) {
      f.print("4");
    }
    else if (binChunk1 == 0B0101||binChunk1 == 0b10100101) {
      f.print("5");
    }
    else if (binChunk1 == 0B0110||binChunk1 == 0b10010110) {
      f.print("6");
    }
    else if (binChunk1 == 0B0111||binChunk1 == 0b10000111) {
      f.print("7");
    }
    else if (binChunk1 == 0B1000||binChunk1 == 0b01111000) {
      f.print("8");
    }
    else if (binChunk1 == 0B1001||binChunk1 == 0b01101001) {
      f.print("9");
    }
    else if (binChunk1 == 0B1010||binChunk1 == 0b01011010) {
      f.print("*");
    }
    else if (binChunk1 == 0B1011||binChunk1 == 0b01001011) {
      f.print("#");
    }
    else if (binChunk1 == 0b1100||binChunk1 == 0b00111100) {
      f.print("F1");
    }
    else if (binChunk1 == 0b1101||binChunk1 == 0b00101101) {
      f.print("F2");
    }
    else if (binChunk1 == 0b1110||binChunk1 == 0b00011110) {
      f.print("F3");
    }
    else if (binChunk1 == 0b1111||binChunk1 == 0b00001111) {
      f.print("F4");
    }
    else {
      f.print("?");
    }
    f.print(",HEX:");
    if (countedBits==8) {
      char hexCHAR[3];
      sprintf(hexCHAR, "%02X", binChunk1);
      f.println(hexCHAR);
    }
    else if (countedBits==4) {
      f.println(binChunk1, HEX);
    }
  }
  else if (countedBits==248) {
    f.println(",");
  }
  else {
    f.println("");
  }

  if (countedBits==248) {
    int startSentinel=magstripe.indexOf("11010");
    int endSentinel=(magstripe.lastIndexOf("11111")+4);
    int magStart=0;
    int magEnd=1;
    //f.print("<pre>");
  
    f.print(" * Trying \"Forward\" Swipe,");
    magStart=startSentinel;
    magEnd=endSentinel;
    f.println(aba2str(magstripe,magStart,magEnd,"\"Forward\" Swipe"));
    
    f.print(" * Trying \"Reverse\" Swipe,");
    char magchar[249];
    magstripe.toCharArray(magchar,249);
    magstripe=String(strrev(magchar));
    //f.println(String()+"Reverse: "+magstripe);
    magStart=magstripe.indexOf("11010");
    magEnd=(magstripe.lastIndexOf("11111")+4);
    f.println(aba2str(magstripe,magStart,magEnd,"\"Reverse\" Swipe"));
  
}
  
  unknown=false;
  binChunk3="";
  binChunk2exists=false;
  binChunk1 = 0; binChunk2 = 0;
  cardChunk1 = 0; cardChunk2 = 0;
  binChunk2len=0;

  f.close(); //done

}

#include "api.h"

void settingsPage()
{
  if(!server.authenticate(update_username, update_password))
    return server.requestAuthentication();
  String accesspointmodeyes;
  String accesspointmodeno;
  if (accesspointmode==1){
    accesspointmodeyes=" checked=\"checked\"";
    accesspointmodeno="";
  }
  else {
    accesspointmodeyes="";
    accesspointmodeno=" checked=\"checked\"";
  }
  String ftpenabledyes;
  String ftpenabledno;
  if (ftpenabled==1){
    ftpenabledyes=" checked=\"checked\"";
    ftpenabledno="";
  }
  else {
    ftpenabledyes="";
    ftpenabledno=" checked=\"checked\"";
  }
  String ledenabledyes;
  String ledenabledno;
  if (ledenabled==1){
    ledenabledyes=" checked=\"checked\"";
    ledenabledno="";
  }
  else {
    ledenabledyes="";
    ledenabledno=" checked=\"checked\"";
  }
  String hiddenyes;
  String hiddenno;
  if (hidden==1){
    hiddenyes=" checked=\"checked\"";
    hiddenno="";
  }
  else {
    hiddenyes="";
    hiddenno=" checked=\"checked\"";
  }
  String safemodeyes;
  String safemodeno;
  if (safemode==1){
    safemodeyes=" checked=\"checked\"";
    safemodeno="";
  }
  else {
    safemodeyes="";
    safemodeno=" checked=\"checked\"";
  }
  server.send(200, "text/html", 
  String()+
  F(
  "<!DOCTYPE HTML>"
  "<html>"
  "<head>"
  "<meta name = \"viewport\" content = \"width = device-width, initial-scale = 1.0, maximum-scale = 1.0, user-scalable=0\">"
  "<title>ESP-RFID-Tool Settings</title>"
  "<style>"
  "\"body { background-color: #808080; font-family: Arial, Helvetica, Sans-Serif; Color: #000000; }\""
  "</style>"
  "</head>"
  "<body>"
  "<a href=\"/\"><- BACK TO INDEX</a><br><br>"
  "<h1>ESP-RFID-Tool Settings</h1>"
  "<a href=\"/restoredefaults\"><button>Restore Default Configuration</button></a>"
  "<hr>"
  "<FORM action=\"/settings\"  id=\"configuration\" method=\"post\">"
  "<P>"
  "<b>WiFi Configuration:</b><br><br>"
  "<b>Network Type</b><br>"
  )+
  F("Access Point Mode: <INPUT type=\"radio\" name=\"accesspointmode\" value=\"1\"")+accesspointmodeyes+F("><br>"
  "Join Existing Network: <INPUT type=\"radio\" name=\"accesspointmode\" value=\"0\"")+accesspointmodeno+F("><br><br>"
  "<b>Hidden<br></b>"
  "Yes <INPUT type=\"radio\" name=\"hidden\" value=\"1\"")+hiddenyes+F("><br>"
  "No <INPUT type=\"radio\" name=\"hidden\" value=\"0\"")+hiddenno+F("><br><br>"
  "SSID: <input type=\"text\" name=\"ssid\" value=\"")+ssid+F("\" maxlength=\"31\" size=\"31\"><br>"
  "Password: <input type=\"password\" name=\"password\" value=\"")+password+F("\" maxlength=\"64\" size=\"31\"><br>"
  "Channel: <select name=\"channel\" form=\"configuration\"><option value=\"")+channel+"\" selected>"+channel+F("</option><option value=\"1\">1</option><option value=\"2\">2</option><option value=\"3\">3</option><option value=\"4\">4</option><option value=\"5\">5</option><option value=\"6\">6</option><option value=\"7\">7</option><option value=\"8\">8</option><option value=\"9\">9</option><option value=\"10\">10</option><option value=\"11\">11</option><option value=\"12\">12</option><option value=\"13\">13</option><option value=\"14\">14</option></select><br><br>"
  "IP: <input type=\"text\" name=\"local_IPstr\" value=\"")+local_IPstr+F("\" maxlength=\"16\" size=\"31\"><br>"
  "Gateway: <input type=\"text\" name=\"gatewaystr\" value=\"")+gatewaystr+F("\" maxlength=\"16\" size=\"31\"><br>"
  "Subnet: <input type=\"text\" name=\"subnetstr\" value=\"")+subnetstr+F("\" maxlength=\"16\" size=\"31\"><br><br>"
  "<hr>"
  "<b>Web Interface Administration Settings:</b><br><br>"
  "Username: <input type=\"text\" name=\"update_username\" value=\"")+update_username+F("\" maxlength=\"31\" size=\"31\"><br>"
  "Password: <input type=\"password\" name=\"update_password\" value=\"")+update_password+F("\" maxlength=\"64\" size=\"31\"><br><br>"
  "<hr>"
  "<b>FTP Server Settings</b><br>"
  "<small>Changes require a reboot.</small><br>"
  "Enabled <INPUT type=\"radio\" name=\"ftpenabled\" value=\"1\"")+ftpenabledyes+F("><br>"
  "Disabled <INPUT type=\"radio\" name=\"ftpenabled\" value=\"0\"")+ftpenabledno+F("><br>"
  "FTP Username: <input type=\"text\" name=\"ftp_username\" value=\"")+ftp_username+F("\" maxlength=\"31\" size=\"31\"><br>"
  "FTP Password: <input type=\"password\" name=\"ftp_password\" value=\"")+ftp_password+F("\" maxlength=\"64\" size=\"31\"><br><br>"
  "<hr>"
  "<b>Power LED:</b><br>"
  "<small>Changes require a reboot.</small><br>"
  "Enabled <INPUT type=\"radio\" name=\"ledenabled\" value=\"1\"")+ledenabledyes+F("><br>"
  "Disabled <INPUT type=\"radio\" name=\"ledenabled\" value=\"0\"")+ledenabledno+F("><br><br>"
  "<hr>"
  "<b>RFID Capture Log:</b><br>"
  "<small>Useful to change this value to differentiate between facilities during various security assessments.</small><br>"
  "File Name: <input type=\"text\" name=\"logname\" value=\"")+logname+F("\" maxlength=\"30\" size=\"31\"><br>"
  "<hr>"
  "<b>Experimental Settings:</b><br>"
  "<small>Changes require a reboot.</small><br>"
  "<small>Default Buffer Length is 256 bits with an allowed range of 52-4096 bits."
  "<br>Default Experimental TX mode timing is 40us Wiegand Data Pulse Width and a 2ms Wiegand Data Interval with an allowed range of 0-1000."
  "<br>Changing these settings may result in unstable performance.</small><br>"
  "Wiegand RX Buffer Length: <input type=\"number\" name=\"bufferlength\" value=\"")+bufferlength+F("\" maxlength=\"30\" size=\"31\" min=\"52\" max=\"4096\"> bit(s)<br>"
  "Wiegand RX Packet Length: <input type=\"number\" name=\"rxpacketgap\" value=\"")+rxpacketgap+F("\" maxlength=\"30\" size=\"31\" min=\"1\" max=\"4096\"> millisecond(s)<br>"
  "Experimental TX Wiegand Data Pulse Width: <input type=\"number\" name=\"txdelayus\" value=\"")+txdelayus+F("\" maxlength=\"30\" size=\"31\" min=\"0\" max=\"1000\"> microsecond(s)<br>"
  "Experimental TX Wiegand Data Interval: <input type=\"number\" name=\"txdelayms\" value=\"")+txdelayms+F("\" maxlength=\"30\" size=\"31\" min=\"0\" max=\"1000\"> millisecond(s)<br>"
  "<hr>"
  "<b>Safe Mode:</b><br>"
  "<small>Enable to reboot the device after every capture.<br>Disable to avoid missing quick consecutive captures such as keypad entries.</small><br>"
  "Enabled <INPUT type=\"radio\" name=\"safemode\" value=\"1\"")+safemodeyes+F("><br>"
  "Disabled <INPUT type=\"radio\" name=\"safemode\" value=\"0\"")+safemodeno+F("><br><br>"
  "<hr>"
  "<INPUT type=\"radio\" name=\"SETTINGS\" value=\"1\" hidden=\"1\" checked=\"checked\">"
  "<INPUT type=\"submit\" value=\"Apply Settings\">"
  "</FORM>"
  "<br><a href=\"/reboot\"><button>Reboot Device</button></a>"
  "</P>"
  "</body>"
  "</html>"
  )
  );
}

void handleSettings()
{
  if (server.hasArg("SETTINGS")) {
    handleSubmitSettings();
  }
  else {
    settingsPage();
  }
}

void returnFail(String msg)
{
  server.sendHeader("Connection", "close");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(500, "text/plain", msg + "\r\n");
}

void handleSubmitSettings()
{
  Serial.println("Hit handleSubmitSettings()");
  String SETTINGSvalue;

  if (!server.hasArg("SETTINGS")) return returnFail("BAD ARGS");
  
  SETTINGSvalue = server.arg("SETTINGS");
  accesspointmode = server.arg("accesspointmode").toInt();
  server.arg("ssid").toCharArray(ssid, 32);
  server.arg("password").toCharArray(password, 64);
  channel = server.arg("channel").toInt();
  hidden = server.arg("hidden").toInt();
  server.arg("local_IPstr").toCharArray(local_IPstr, 16);
  server.arg("gatewaystr").toCharArray(gatewaystr, 16);
  server.arg("subnetstr").toCharArray(subnetstr, 16);
  server.arg("update_username").toCharArray(update_username, 32);
  server.arg("update_password").toCharArray(update_password, 64);
  server.arg("ftp_username").toCharArray(ftp_username, 32);
  server.arg("ftp_password").toCharArray(ftp_password, 64);
  ftpenabled = server.arg("ftpenabled").toInt();
  ledenabled = server.arg("ledenabled").toInt();
  server.arg("logname").toCharArray(logname, 31);
  bufferlength = server.arg("bufferlength").toInt();
  rxpacketgap = server.arg("rxpacketgap").toInt();
  txdelayus = server.arg("txdelayus").toInt();
  txdelayms = server.arg("txdelayms").toInt();
  safemode = server.arg("safemode").toInt();
  
  if (SETTINGSvalue == "1") {
    saveConfig();
    server.send(200, "text/html", F("<a href=\"/\"><- BACK TO INDEX</a><br><br><a href=\"/reboot\"><button>Reboot Device</button></a><br><br>Settings have been saved.<br>Some setting may require manually rebooting before taking effect.<br>If network configuration has changed then be sure to connect to the new network first in order to access the web interface."));
    delay(50);
    loadConfig();
  }
  else if (SETTINGSvalue == "0") {
    settingsPage();
  }
  else {
    returnFail("Bad SETTINGS value");
  }
}

bool loadDefaults() {
  Serial.println("Hit loadDefaults()");
  StaticJsonDocument<500> json;
  json["version"] = version;
  json["accesspointmode"] = "1";
  json["ssid"] = "ESPRFIDTOOL_NodeMCU";
  json["password"] = "thereisnospoon";
  json["channel"] = "6";
  json["hidden"] = "0";
  json["local_IP"] = "192.168.4.1";
  json["gateway"] = "192.168.4.1";
  json["subnet"] = "255.255.255.0";
  json["update_username"] = "admin";
  json["update_password"] = "rfidtool";
  json["ftp_username"] = "ftp-admin";
  json["ftp_password"] = "rfidtool";
  json["ftpenabled"] = "0";
  json["ledenabled"] = "1";
  json["logname"] = "log.txt";
  json["bufferlength"] = "256";
  json["rxpacketgap"] = "15";
  json["txdelayus"] = "40";
  json["txdelayms"] = "2";
  json["safemode"] = "0";
  File configFile = SPIFFS.open("/esprfidtool.json", "w");
  if(!configFile)Serial.println("loadDefault() opened config file for writing FALSE");
  else Serial.println("loadDefault() opened config file for writing TRUE");
  serializeJson(json,configFile);
  configFile.close();
  loadConfig();
}

bool loadConfig() {
  Serial.println("Hit loadConfig()");
  File configFile = SPIFFS.open("/esprfidtool.json", "r");
  if (!configFile) {
    Serial.println("No configFile");
    delay(3500);
    Serial.println("Loading Default Config");
    loadDefaults();
    return false;
  }

  size_t size = configFile.size();

  std::unique_ptr<char[]> buf(new char[size]);
  configFile.readBytes(buf.get(), size);
  StaticJsonDocument<500> json;
  deserializeJson(json, buf.get());
  if (!json["version"]) {
    Serial.println("No version.");
    delay(3500);
    loadDefaults();
    Serial.println("No version. Restarting");
    ESP.restart();
  }

  //Resets config to factory defaults on an update.
  if (json["version"]!=version) {
    Serial.println("Version difference.");
    delay(3500);
    loadDefaults();
    Serial.println("Version difference. Restarting");
    ESP.restart();
  }

  strcpy(ssid, (const char*)json["ssid"]);
  strcpy(password, (const char*)json["password"]);
  channel = json["channel"];
  hidden = json["hidden"];
  accesspointmode = json["accesspointmode"];
  strcpy(local_IPstr, (const char*)json["local_IP"]);
  strcpy(gatewaystr, (const char*)json["gateway"]);
  strcpy(subnetstr, (const char*)json["subnet"]);

  strcpy(update_username, (const char*)json["update_username"]);
  strcpy(update_password, (const char*)json["update_password"]);

  strcpy(ftp_username, (const char*)json["ftp_username"]);
  strcpy(ftp_password, (const char*)json["ftp_password"]);
  ftpenabled = json["ftpenabled"];
  ledenabled = json["ledenabled"];
  strcpy(logname, (const char*)json["logname"]);
  bufferlength = json["bufferlength"];
  rxpacketgap = json["rxpacketgap"];
  txdelayus = json["txdelayus"];
  txdelayms = json["txdelayms"];
  safemode = json["safemode"];
 
  IPAddress local_IP;
  local_IP.fromString(local_IPstr);
  IPAddress gateway;
  gateway.fromString(gatewaystr);
  IPAddress subnet;
  subnet.fromString(subnetstr);
  WiFi.persistent(false);
  ESP.eraseConfig();
// Determine if set to Access point mode
  if (accesspointmode == 1) {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_AP);
    Serial.print("Starting Access Point ... ");
    Serial.println(WiFi.softAP(ssid, password, channel, hidden) ? "Success" : "Failed!");
    Serial.print("Setting up Network Configuration ... ");
    WiFi.softAPConfig(local_IP, gateway, subnet);
    Serial.print("IP address = ");
    Serial.println(WiFi.softAPIP());
  }
// or Join existing network
  else if (accesspointmode != 1) {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_STA);
    WiFi.config(local_IP, gateway, subnet);
    WiFi.begin(ssid, password);
    WiFi.reconnect();
  }
  configFile.close();
  return true;
}

bool saveConfig() {
  Serial.println("Hit saveConfig()");
  StaticJsonDocument<500> json;
  json["version"] = version;
  json["accesspointmode"] = accesspointmode;
  json["ssid"] = ssid;
  json["password"] = password;
  json["channel"] = channel;
  json["hidden"] = hidden;
  json["local_IP"] = local_IPstr;
  json["gateway"] = gatewaystr;
  json["subnet"] = subnetstr;
  json["update_username"] = update_username;
  json["update_password"] = update_password;
  json["ftp_username"] = ftp_username;
  json["ftp_password"] = ftp_password;
  json["ftpenabled"] = ftpenabled;
  json["ledenabled"] = ledenabled;
  json["logname"] = logname;
  json["bufferlength"] = bufferlength;
  json["rxpacketgap"] = rxpacketgap;
  json["txdelayus"] = txdelayus;
  json["txdelayms"] = txdelayms;
  json["safemode"] = safemode;
  File configFile = SPIFFS.open("/esprfidtool.json", "w");
  serializeJson(json,configFile);
  configFile.close();
  return true;
}

File fsUploadFile;
String webString;

void ListLogs(){
  String directory;
  directory="/";
  FSInfo fs_info;
  SPIFFS.info(fs_info);
  String total;
  total=fs_info.totalBytes;
  String used;
  used=fs_info.usedBytes;
  String freespace;
  freespace=fs_info.totalBytes-fs_info.usedBytes;
  Dir dir = SPIFFS.openDir(directory);
  String FileList = String()+F("<a href=\"/\"><- BACK TO INDEX</a><br><br>File System Info Calculated in Bytes<br><b>Total:</b> ")+total+" <b>Free:</b> "+freespace+" "+" <b>Used:</b> "+used+"<br><br><small>NOTE: Larger log files will need to be downloaded instead of viewed from the browser.</small><br><table border='1'><tr><td><b>Display File Contents</b></td><td><b>Size in Bytes</b></td><td><b>Download File</b></td><td><b>Delete File</b></td></tr>";
  while (dir.next()) {
    String FileName = dir.fileName();
    File f = dir.openFile("r");
    FileList += " ";
    if((!FileName.startsWith("/payloads/"))&&(!FileName.startsWith("/esploit.json"))&&(!FileName.startsWith("/esportal.json"))&&(!FileName.startsWith("/esprfidtool.json"))&&(!FileName.startsWith("/config.json"))) FileList += "<tr><td><a href=\"/viewlog?payload="+FileName+"\">"+FileName+"</a></td>"+"<td>"+f.size()+"</td><td><a href=\""+FileName+"\"><button>Download File</button></td><td><a href=\"/deletelog?payload="+FileName+"\"><button>Delete File</button></td></tr>";
    f.close();
  }
  FileList += "</table>";
  server.send(200, "text/html", FileList);
}

bool RawFile(String rawfile) {
  if (SPIFFS.exists(rawfile)) {
    if(!server.authenticate(update_username, update_password)){
      server.requestAuthentication();}
    File file = SPIFFS.open(rawfile, "r");
    size_t sent = server.streamFile(file, "application/octet-stream");
    file.close();
    return true;
  }
  return false;
}

void ViewLog(){
  webString="";
  String payload;
  String ShowPL;
  payload += server.arg(0);
  File f = SPIFFS.open(payload, "r");
  String webString = f.readString();
  f.close();
  ShowPL = String()+F(
    "<html><head></head><body>"
    "<a href=\"/\"><- BACK TO INDEX</a><br><br>"
    "<a href=\"/logs\">List Exfiltrated Data</a> - <a href=\"/experimental\">Experimental TX Mode</a> - <a href=\"/data-convert\">Data Conversion Tools</a><br><br>"
    "<FORM action=\"/api/tx/bin\" id=\"api_tx\" method=\"get\"  target=\"_blank\">"
      "<small>Binary: </small><INPUT form=\"api_tx\" type=\"text\" name=\"binary\" value=\"\" pattern=\"[01,]{1,}\" required title=\"Allowed characters(0,1,\",\"), must not be empty\" minlength=\"1\" size=\"52\"> "
      "<INPUT form=\"api_tx\" type=\"submit\" value=\"Transmit\"><br>"
      "<small>Pulse Width: </small><INPUT form=\"api_tx\" type=\"number\" name=\"pulsewidth\" value=\"40\" minlength=\"1\" min=\"0\" size=\"8\"><small>us</small> "
      "<small>Data Interval: </small><INPUT form=\"api_tx\" type=\"number\" name=\"interval\" value=\"2000\" minlength=\"1\" min=\"0\" size=\"8\"><small>us</small> "
      "<small>Delay Between Packets: </small><INPUT form=\"api_tx\" type=\"number\" name=\"wait\" value=\"100000\" minlength=\"1\" min=\"0\" size=\"8\"><small>us</small><br>"
      "<INPUT form=\"api_tx\" type=\"hidden\" name=\"prettify\" id=\"prettify\" value=\"1\">"
    "</FORM>"
    "<small>Use commas to separate the binary for transmitting multiple packets(useful for sending multiple keypresses for imitating keypads)</small><br>"
    "<hr>"
    "<a href=\"")+payload+F("\"><button>Download File</button><a><small> - </small><a href=\"/deletelog?payload=")+payload+F("\"><button>Delete File</button></a>"
    "<pre>")
    +payload+
    F("\n"
    "Note: Preambles shown are only a guess based on card length and may not be accurate for every card format.\n"
    "-----\n")
    +webString+
    F("</pre></body></html>")
    ;
  webString="";
  server.send(200, "text/html", ShowPL);
}

void ViewLogRAW(){
  webString="";
  String payload;
  String ShowPL;
  payload += server.arg(0);
  File f = SPIFFS.open(payload, "r");
  String webString = f.readString();
  f.close();
  ShowPL = String()+webString;
  Serial.println(webString);
  webString="";
  server.send(200, "text/html", webString);
}

// Start Networking
void setup() {
  Serial.begin(9600);
  Serial.println(F("....."));
  Serial.println(String()+F("ESP-RFID-Tool (NodeMCU) v")+version);
  //SPIFFS.format();
  
  SPIFFS.begin();
  
  //loadDefaults(); //uncomment to restore default settings if double reset fails for some reason

  //Jump RESTORE_DEFAULTS_PIN to GND while powering on device to reset the device to factory defaults
  pinMode(RESTORE_DEFAULTS_PIN, INPUT_PULLUP);
  jumperState = digitalRead(RESTORE_DEFAULTS_PIN);
  if (jumperState == LOW) {
    Serial.println(String()+F("Pin ")+RESTORE_DEFAULTS_PIN+F("Grounded"));
    Serial.println(F("Loading default config..."));
    loadDefaults();
  }
  
  loadConfig();
  Serial.println(F("Passed load config."));
  Serial.print("Buffer Length = ");
  Serial.println(bufferlength);
  if(!wg.begin(DATA0,DATA1,bufferlength,rxpacketgap)) {       
    Serial.println(F("Could not begin Wiegand logging,"));            
    Serial.println(F("Out of memory!"));
  }
Serial.println("build page 1");
//Set up Web Pages
  server.on("/", file_index);
  server.on("/index.html", file_index);
  server.on("/bootstrap.min.css", file_bootstrap);
  server.on("bootstrap.min.css", file_bootstrap);
  server.on("/dashboard.css", file_dashboard);
  server.on("dashboard.css", file_dashboard);
  Serial.println("build page 2");
  server.onNotFound([]() {
    if (!RawFile(server.uri()))
      server.send(404, "text/plain", F("Error 404 File Not Found"));
  });
Serial.println("build page 3");
  server.on("/settings", handleSettings);
Serial.println("build page 4");
  server.on("/firmware", [](){
    server.send(200, "text/html", String()+F("<html><body style=\"height: 100%;\"><a href=\"/\"><- BACK TO INDEX</a><br><br>Open Arduino IDE.<br>Pull down \"Sketch\" Menu then select \"Export Compiled Binary\".<br>On this page click \"Browse\", select the binary you exported earlier, then click \"Update\".<br>You may need to manually reboot the device to reconnect.<br><iframe style =\"border: 0; height: 100%;\" src=\"http://")+local_IPstr+F(":1337/update\"><a href=\"http://")+local_IPstr+F(":1337/update\">Click here to Upload Firmware</a></iframe></body></html>"));
  });
Serial.println("build page 5");
  server.on("/restoredefaults", [](){
    server.send(200, "text/html", F("<html><body>This will restore the device to the default configuration.<br><br>Are you sure?<br><br><a href=\"/restoredefaults/yes\">YES</a> - <a href=\"/\">NO</a></body></html>"));
  });

  server.on("/restoredefaults/yes", [](){
    if(!server.authenticate(update_username, update_password))
      return server.requestAuthentication();
    server.send(200, "text/html", F("<a href=\"/\"><- BACK TO INDEX</a><br><br>Network<br>---<br>SSID: <b>ESP-RFID-Tool</b><br><br>Administration<br>---<br>USER: <b>admin</b> PASS: <b>rfidtool</b>"));
    delay(50);
    loadDefaults();
    ESP.restart();
  });

  server.on("/deletelog", [](){
    String deletelog;
    deletelog += server.arg(0);
    server.send(200, "text/html", String()+F("<html><body>This will delete the file: ")+deletelog+F(".<br><br>Are you sure?<br><br><a href=\"/deletelog/yes?payload=")+deletelog+F("\">YES</a> - <a href=\"/\">NO</a></body></html>"));
  });

  server.on("/viewlog", ViewLog);
  server.on("/viewlogRAW", ViewLogRAW);

  server.on("/deletelog/yes", [](){
    if(!server.authenticate(update_username, update_password))
      return server.requestAuthentication();
    //String deletelog;
    //deletelog += server.arg(0);
    //if (!deletelog.startsWith("/payloads/")){ 
    String deletelog = logname;
    if(SPIFFS.remove(deletelog)){
      server.send(200, "text/html", String()+F("<a href=\"/\"><- BACK TO INDEX</a><br><br><a href=\"/logs\">List Exfiltrated Data</a><br><br>Deleting file: ")+deletelog);
    }else{
      server.send(200, "text/html", String()+F("Failed to delete log :("));
    }
    delay(50);
  });

  server.on("/format", [](){
    server.send(200, "text/html", F("<html><body><a href=\"/\"><- BACK TO INDEX</a><br><br>This will reformat the SPIFFS File System.<br><br>Are you sure?<br><br><a href=\"/format/yes\">YES</a> - <a href=\"/\">NO</a></body></html>"));
  });

  server.on("/logs", ListLogs);

  server.on("/reboot", [](){
    if(!server.authenticate(update_username, update_password))
    return server.requestAuthentication();
    server.send(200, "text/html", F("<a href=\"/\"><- BACK TO INDEX</a><br><br>Rebooting Device..."));
    delay(50);
    ESP.restart();
  });
  
  server.on("/format/yes", [](){
    if(!server.authenticate(update_username, update_password))
      return server.requestAuthentication();
    server.send(200, "text/html", F("<a href=\"/\"><- BACK TO INDEX</a><br><br>Formatting file system: This may take up to 90 seconds"));
    delay(50);
    SPIFFS.format();
    saveConfig();
  });
  
  server.on("/help", []() {
    server.send_P(200, "text/html", HelpText);
  });
  
  server.on("/license", []() {
    server.send_P(200, "text/html", License);
  });
  
  server.on("/data-convert", [](){
    if (server.hasArg("bin2hexHTML")) {
      int bin2hexBUFFlen=(((server.arg("bin2hexHTML")).length())+1);
      char bin2hexCHAR[bin2hexBUFFlen];
      (server.arg("bin2hexHTML")).toCharArray(bin2hexCHAR,bin2hexBUFFlen);
      dataCONVERSION+=String()+F("Binary: ")+bin2hexCHAR+F("<br><br>");
      String hexTEMP="";
      int binCOUNT=(bin2hexBUFFlen-1);
      for (int currentBINpos=0; currentBINpos<binCOUNT; currentBINpos=currentBINpos+4) {
        char hexCHAR[2];
        char tempNIBBLE[5];
        strncpy(tempNIBBLE, &bin2hexCHAR[currentBINpos], 4);
        tempNIBBLE[4]='\0';
        sprintf(hexCHAR, "%X", (strtol(tempNIBBLE, NULL, 2)));
        hexTEMP+=hexCHAR;
      }
      dataCONVERSION+=String()+F("Hexadecimal: ")+hexTEMP+F("<br><small>You may want to drop the leading zero(if there is one) and if your cloning software does not handle it for you.</small><br><br>");
      hexTEMP="";     
      dataCONVERSION+=F("<br><br>");
      bin2hexBUFFlen=0;
    }
    if (server.hasArg("hex2binHTML")) {
      int hex2binBUFFlen=(((server.arg("hex2binHTML")).length())+1);
      char hex2binCHAR[hex2binBUFFlen];
      (server.arg("hex2binHTML")).toCharArray(hex2binCHAR,hex2binBUFFlen);

      dataCONVERSION+=String()+F("Hexadecimal: ")+hex2binCHAR+F("<br><br>");

      String binTEMP="";

      int charCOUNT=(hex2binBUFFlen-1);
      for (int currentHEXpos=0; currentHEXpos<charCOUNT; currentHEXpos++) {
        char binCHAR[5];
        char tempHEX[2];
        strncpy(tempHEX, &hex2binCHAR[currentHEXpos], 1);
        tempHEX[1]='\0';
        int decimal=(unsigned char)strtoul(tempHEX, NULL, 16);
        itoa(decimal,binCHAR,2);
        while (strlen(binCHAR) < 4) {
          char *dup;
          sprintf(binCHAR,"%s%s","0",(dup=strdup(binCHAR)));
          free(dup);
        }
        binTEMP+=binCHAR;
      }

      dataCONVERSION+=String()+F("Binary: ")+binTEMP+F("<br><br>");
      binTEMP="";
      
      dataCONVERSION+=F("<br><br>");
      
      hex2binBUFFlen=0;
    }
    
    if (server.hasArg("abaHTML")) {
      String abaHTML=(server.arg("abaHTML"));

      dataCONVERSION="Trying \"Forward\" Swipe<br>";
      dataCONVERSION+=("Forward Binary:"+abaHTML+"<br>");
      int abaStart=abaHTML.indexOf("11010");
      int abaEnd=(abaHTML.lastIndexOf("11111")+4);
      dataCONVERSION+=aba2str(abaHTML,abaStart,abaEnd,"\"Forward\" Swipe");
      
      dataCONVERSION+=" * Trying \"Reverse\" Swipe<br>";
      int abaBUFFlen=((abaHTML.length())+1);
      char abachar[abaBUFFlen];
      abaHTML.toCharArray(abachar,abaBUFFlen);
      abaHTML=String(strrev(abachar));
      dataCONVERSION+=("Reversed Binary:"+abaHTML+"<br>");
      abaStart=abaHTML.indexOf("11010");
      abaEnd=(abaHTML.lastIndexOf("11111")+4);
      dataCONVERSION+=aba2str(abaHTML,abaStart,abaEnd,"\"Reverse\" Swipe");
    
      //dataCONVERSION+=(String()+F(" * You can verify the data at the following URL:<br><a target=\"_blank\" href=\"https://www.legacysecuritygroup.com/aba-decode.php?binary=")+abaHTML+F("\">https://www.legacysecuritygroup.com/aba-decode.php?binary=")+abaHTML+F("</a>"));
      dataCONVERSION.replace("*", "<br><br>");
      dataCONVERSION.replace(":", ": ");

      abaHTML="";
      abaStart=0;
      abaEnd=0;
    }
    file_datatools();   
    dataCONVERSION="";
  });
  #include "api_server.h"

  /*server.on("/statustx", [](){
    StaticJsonDocument<500> json;
    json["status"] = TXstatus;
    json["message"] = experimentalStatus;
    hereherehere
    server.send(200, "text/html", F("<html><body>This will kill any ongoing transmissions.<br><br>Are you sure?<br><br><a href=\"/stoptx/yes\">YES</a> - <a href=\"/\">NO</a></body></html>"));
  });*/

  server.on("/testEP", [](){
    //server.send(200, "text/html", intTobin(29));
  });
  

  server.on("/stoptx", [](){
    server.send(200, "text/html", F("<html><body>This will kill any ongoing transmissions.<br><br>Are you sure?<br><br><a href=\"/stoptx/yes\">YES</a> - <a href=\"/\">NO</a></body></html>"));
  });

  server.on("/stoptx/yes", [](){
    TXstatus=0;
    experimentalStatus = "";
    server.send(200, "text/html", F("<a href=\"/\"><- BACK TO INDEX</a><br><br><a href=\"/experimental\"><- BACK TO EXPERIMENTAL TX MODE</a><br><br>All transmissions have been stopped."));
  });

  server.on("/experimental", [](){   
    //experimentalStatus="Awaiting Instructions";
    if (server.hasArg("pinHTML")||server.hasArg("bruteEND")) {
      pinHTML=server.arg("pinHTML");
      int pinBITS=server.arg("pinBITS").toInt();
      int pinHTMLDELAY=server.arg("pinHTMLDELAY").toInt();
      int bruteforcing;
      int brutePAD=(server.arg("bruteSTART").length());
      if (server.hasArg("bruteSTART")) {
        bruteforcing=1;
      }
      else {
        bruteforcing=0;
      }
      TXstatus=1;
      
      wg.pause();
      digitalWrite(DATA0, HIGH);
      pinMode(DATA0,OUTPUT);
      digitalWrite(DATA1, HIGH);
      pinMode(DATA1,OUTPUT);

      pinHTML.replace("F1","C");
      pinHTML.replace("F2","D");
      pinHTML.replace("F3","E");
      pinHTML.replace("F4","F");

      experimentalStatus=String()+"Transmitting "+pinBITS+"bit Wiegand Format PIN: "+pinHTML+" with a "+pinHTMLDELAY+"ms delay between \"keypresses\"";
      delay(50);
      
      int bruteSTART;
      int bruteEND;
      if (server.hasArg("bruteSTART")) {
        bruteSTART=server.arg("bruteSTART").toInt();
      }
      else {
        bruteSTART=0;
      }
      
      if (server.hasArg("bruteEND")) {
        bruteEND=server.arg("bruteEND").toInt();
      }
      else {
        bruteEND=0;
      }

      if (server.hasArg("bruteSTART")) {
        server.send(200, "text/html", String()+"<a href=\"/\"><- BACK TO INDEX</a><br><br><a href=\"/experimental\"><- BACK TO EXPERIMENTAL TX MODE</a><br><br>Brute forcing "+pinBITS+"bit Wiegand Format PIN from "+(server.arg("bruteSTART"))+" to "+(server.arg("bruteEND"))+" with a "+pinHTMLDELAY+"ms delay between \"keypresses\"<br>This may take a while, your device will be busy until the sequence has been completely transmitted!<br>Please \"STOP CURRENT TRANSMISSION\" before attempting to use your device or simply wait for the transmission to finish.<br>You can view if the brute force attempt has completed by returning to the Experimental TX page and checking the status located under \"Transmit Status\"<br><br><a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>");
        delay(50);
      }

      String bruteSTARTchar="";
      String bruteENDchar="";
      if (server.hasArg("bruteSTARTchar")&&(server.arg("bruteSTARTchar")!="")) {
        bruteSTARTchar=(server.arg("bruteSTARTchar"));
        bruteSTARTchar.replace("F1","C");
        bruteSTARTchar.replace("F2","D");
        bruteSTARTchar.replace("F3","E");
        bruteSTARTchar.replace("F4","F");
      }
      if (server.hasArg("bruteENDchar")&&(server.arg("bruteENDchar")!="")) {
        bruteENDchar=(server.arg("bruteENDchar"));
        bruteENDchar=(server.arg("bruteENDchar"));
        bruteENDchar.replace("F1","C");
        bruteENDchar.replace("F2","D");
        bruteENDchar.replace("F3","E");
        bruteENDchar.replace("F4","F");
      }

      unsigned long bruteFAILdelay=0;
      unsigned long bruteFAILS=0;
      int bruteFAILmultiplier=0;
      int bruteFAILmultiplierCURRENT=0;
      int bruteFAILmultiplierAFTER=0;
      int delayAFTERpin=0;
      int bruteFAILSmax=0;
      bruteFAILSmax=(server.arg("bruteFAILSmax")).toInt();
      delayAFTERpin=(server.arg("delayAFTERpin")).toInt();
      bruteFAILdelay=(server.arg("bruteFAILdelay")).toInt();
      bruteFAILmultiplier=(server.arg("bruteFAILmultiplier")).toInt();
      bruteFAILmultiplierAFTER=(server.arg("bruteFAILmultiplierAFTER")).toInt();

      for (int brute=bruteSTART; brute<=bruteEND; brute++) {

        if (bruteforcing==1) {
          pinHTML=String(brute);
          while (pinHTML.length()<brutePAD) {
            pinHTML="0"+pinHTML;
          }
        }

        if (bruteSTARTchar!="") {
          pinHTML=bruteSTARTchar+pinHTML;
        }

        if (bruteENDchar!="") {
          pinHTML=pinHTML+bruteENDchar;
        }
          
        for (int i=0; i<=pinHTML.length(); i++) {
          if (pinHTML.charAt(i) == '0') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0000");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"11110000");
            }
          }
          else if (pinHTML.charAt(i) == '1') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0001");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"11100001");
            }
          }
          else if (pinHTML.charAt(i) == '2') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0010");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"11010010");
            }
          }
          else if (pinHTML.charAt(i) == '3') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0011");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"11000011");
            }
          }
          else if (pinHTML.charAt(i) == '4') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0100");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"10110100");
            }
          }
          else if (pinHTML.charAt(i) == '5') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0101");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"10100101");
            }
          }
          else if (pinHTML.charAt(i) == '6') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0110");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"10010110");
            }
          }
          else if (pinHTML.charAt(i) == '7') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"0111");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"10000111");
            }
          }
          else if (pinHTML.charAt(i) == '8') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1000");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"01111000");
            }
          }
          else if (pinHTML.charAt(i) == '9') {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1001");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"01101001");
            }
          }
          else if ((pinHTML.charAt(i) == '*')||(pinHTML.charAt(i) == 'A')) {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1010");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"01011010");
            }
          }
          else if ((pinHTML.charAt(i) == '#')||(pinHTML.charAt(i) == 'B')) {
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1011");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"01001011");
            }
          }
          else if (pinHTML.charAt(i) == 'C') { //F1
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1100");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"00111100");
            }
          }
          else if (pinHTML.charAt(i) == 'D') { //F2
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1101");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"00101101");
            }
          }
          else if (pinHTML.charAt(i) == 'E') { //F3
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1110");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"00011110");
            }
          }
          else if (pinHTML.charAt(i) == 'F') { //F4
            if (pinBITS==4) {
              pinSEND(pinHTMLDELAY,"1111");
            }
            else if (pinBITS==8) {
              pinSEND(pinHTMLDELAY,"00001111");
            }
          }
        }

        server.handleClient();
        if (TXstatus!=1) {
          break;
        }

        bruteFAILS++;

        if (bruteFAILS>=4294967000) {
          bruteFAILS=(4294966000);
        }
        if (bruteFAILdelay>=4294967000) {
          bruteFAILdelay=(4294966000);
        }
        
        if (bruteFAILmultiplier!=0) {
          bruteFAILmultiplierCURRENT++;
          if (bruteFAILmultiplierCURRENT>=bruteFAILmultiplierAFTER) {
            bruteFAILmultiplierCURRENT=0;
            bruteFAILdelay=(bruteFAILdelay*bruteFAILmultiplier);
          }
        }
        
        if ((bruteFAILS>=bruteFAILSmax)&&(bruteFAILSmax!=0)) {
          delay(bruteFAILdelay*1000);
        }
        else {
          delay(delayAFTERpin);
        }
        
      }
      pinMode(DATA0, INPUT);
      pinMode(DATA1, INPUT);
      wg.clear();
      pinHTML="";
      pinHTMLDELAY=100;
      TXstatus=0;
      bruteforcing=0;
      brutePAD=0;
      bruteSTARTchar="";
      bruteENDchar="";
      bruteFAILdelay=0;
      bruteFAILS=0;
      bruteFAILmultiplier=0;
      bruteFAILmultiplierCURRENT=0;
      bruteFAILmultiplierAFTER=0;
      delayAFTERpin=0;
      bruteFAILSmax=0;
    }


    if (server.hasArg("binHTML")) {
      String binHTML=server.arg("binHTML");
      wg.pause();
      digitalWrite(DATA0, HIGH);
      pinMode(DATA0,OUTPUT);
      digitalWrite(DATA1, HIGH);
      pinMode(DATA1,OUTPUT);

      for (int i=0; i<=binHTML.length(); i++) {
        if (binHTML.charAt(i) == '0') {
          digitalWrite(DATA0, LOW);
          delayMicroseconds(txdelayus);
          digitalWrite(DATA0, HIGH);
        }
        else if (binHTML.charAt(i) == '1') {
          digitalWrite(DATA1, LOW);
          delayMicroseconds(txdelayus);
          digitalWrite(DATA1, HIGH);
        }
        delay(txdelayms);
      }

      pinMode(DATA0, INPUT);
      pinMode(DATA1, INPUT);
      wg.clear();

      experimentalStatus=String()+"Transmitting Binary: "+binHTML;
      binHTML="";
    }

    if (server.arg("fuzzType")=="simultaneous") {

      int fuzzTimes=0;
      dos=0;
      if ((server.arg("fuzzTimes"))=="dos") {
        dos=1;
        server.send(200, "text/html", String()+
        "<a href=\"/\"><- BACK TO INDEX</a><br><br>"
        "<a href=\"/experimental\"><- BACK TO EXPERIMENTAL TX MODE</a><br><br>"
        "Denial of Service mode active.<br>Transmitting D0 and D1 bits simultaneously until stopped."
        "<br>This may take a while, your device will be busy until the sequence has been completely transmitted!"
        "<br>Please \"STOP CURRENT TRANSMISSION\" before attempting to use your device or simply wait for the transmission to finish.<br>"
        "You can view if the fuzzing attempt has completed by returning to the Experimental TX page and checking the status located under \"Transmit Status\"<br><br>"
        "<a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>");
        delay(50);
      }
      else {
        fuzzTimes=server.arg("fuzzTimes").toInt();
        server.send(200, "text/html", String()+
        "<a href=\"/\"><- BACK TO INDEX</a><br><br>"
        "<a href=\"/experimental\"><- BACK TO EXPERIMENTAL TX MODE</a><br><br>"
        "Transmitting D0 and D1 bits simultaneously "+fuzzTimes+" times."
        "<br>This may take a while, your device will be busy until the sequence has been completely transmitted!"
        "<br>Please \"STOP CURRENT TRANSMISSION\" before attempting to use your device or simply wait for the transmission to finish.<br>"
        "You can view if the fuzzing attempt has completed by returning to the Experimental TX page and checking the status located under \"Transmit Status\"<br><br>"
        "<a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>");
        delay(50);
      }
      
      wg.pause();
      digitalWrite(DATA0, HIGH);
      pinMode(DATA0,OUTPUT);
      digitalWrite(DATA1, HIGH);
      pinMode(DATA1,OUTPUT);

      TXstatus=1;

      for (int i=0; i<=fuzzTimes || dos==1; i++) {
        digitalWrite(DATA0, LOW);
        digitalWrite(DATA1, LOW);
        delayMicroseconds(txdelayus);
        digitalWrite(DATA0, HIGH);
        digitalWrite(DATA1, HIGH);
        delay(txdelayms);
        server.handleClient();
        if (TXstatus!=1) {
          break;
        }
      }

      pinMode(DATA0, INPUT);
      pinMode(DATA1, INPUT);
      wg.clear();
      TXstatus=0;
      dos=0;

      //experimentalStatus=String()+"Transmitting D0 and D1 bits simultaneously "+fuzzTimes+" times.";
    }

    if (server.arg("fuzzType")=="alternating") {

      int fuzzTimes=0;
      dos=0;
      if ((server.arg("fuzzTimes"))=="dos") {
        dos=1;
        server.send(200, "text/html", String()+
        "<a href=\"/\"><- BACK TO INDEX</a><br><br>"
        "<a href=\"/experimental\"><- BACK TO EXPERIMENTAL TX MODE</a><br><br>"
        "Denial of Service mode active.<br>Transmitting bits alternating between D0 and D1 until stopped."
        "<br>This may take a while, your device will be busy until the sequence has been completely transmitted!"
        "<br>Please \"STOP CURRENT TRANSMISSION\" before attempting to use your device or simply wait for the transmission to finish.<br>"
        "You can view if the fuzzing attempt has completed by returning to the Experimental TX page and checking the status located under \"Transmit Status\"<br><br>"
        "<a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>");
        delay(50);
      }
      else {
        fuzzTimes=server.arg("fuzzTimes").toInt();
        server.send(200, "text/html", String()+
        "<a href=\"/\"><- BACK TO INDEX</a><br><br>"
        "<a href=\"/experimental\"><- BACK TO EXPERIMENTAL TX MODE</a><br><br>"
        "Transmitting "+fuzzTimes+" bits alternating between D0 and D1."
        "<br>This may take a while, your device will be busy until the sequence has been completely transmitted!"
        "<br>Please \"STOP CURRENT TRANSMISSION\" before attempting to use your device or simply wait for the transmission to finish.<br>"
        "You can view if the fuzzing attempt has completed by returning to the Experimental TX page and checking the status located under \"Transmit Status\"<br><br>"
        "<a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>");
        delay(50);
      }
      
      wg.pause();
      digitalWrite(DATA0, HIGH);
      pinMode(DATA0,OUTPUT);
      digitalWrite(DATA1, HIGH);
      pinMode(DATA1,OUTPUT);

      String binALT="";
      TXstatus=1;

      for (int i=0; i<fuzzTimes || dos==1; i++) {
        if (i%2==0) {
          digitalWrite(DATA0, LOW);
          delayMicroseconds(txdelayus);
          digitalWrite(DATA0, HIGH);
          binALT=binALT+"0";
        }
        else {
           digitalWrite(DATA1, LOW);
           delayMicroseconds(txdelayus);
           digitalWrite(DATA1, HIGH);
           binALT=binALT+"1";
        }
        delay(txdelayms);
        server.handleClient();
        if (TXstatus!=1) {
          break;
        }
      }

      pinMode(DATA0, INPUT);
      pinMode(DATA1, INPUT);
      wg.clear();
      TXstatus=0;
      dos=0;

      //experimentalStatus=String()+"Transmitting alternating bits: "+binALT;
      binALT="";
    }

    if (server.arg("pushType")=="Ground") {
      Serial.end();
      digitalWrite(3,LOW);
      pinMode(3,OUTPUT);
      delay(server.arg("pushTime").toInt());
      pinMode(3,INPUT);
      Serial.begin(9600);

      experimentalStatus=String()+"Grounding \"Push to Open\" wire for "+(server.arg("pushTime").toInt())+"ms.";
    }

    if (server.arg("pushType")=="High") {
      Serial.end();
      digitalWrite(3,HIGH);
      pinMode(3,OUTPUT);
      delay(server.arg("pushTime").toInt());
      pinMode(3,INPUT);
      Serial.begin(9600);

      experimentalStatus=String()+"Outputting 3.3V on \"Push to Open\" wire for "+(server.arg("pushTime").toInt())+"ms.";
    }
    //Send the page to display
    file_txtools();
  });
  server.begin();
  WiFiClient client;
  client.setNoDelay(1);

  Serial.println("Web Server Started");
  MDNS.begin("ESP");
  httpUpdater.setup(&httpServer, update_path, update_username, update_password);
  httpServer.begin();
  MDNS.addService("http", "tcp", 1337);
  
  if (ftpenabled==1){
    ftpSrv.begin(String(ftp_username),String(ftp_password));
  }

  //Start RFID Reader
  pinMode(LED_BUILTIN, OUTPUT);  // LED
  if (ledenabled==1){
    digitalWrite(LED_BUILTIN, LOW);
  }
  else{
    digitalWrite(LED_BUILTIN, HIGH);
  }
}



//Load pages from SPIFFS
void file_index()
{
  File file = SPIFFS.open("/index.html", "r");
  size_t sent = server.streamFile(file, "text/html");  
}

void file_bootstrap()
{
  File file = SPIFFS.open("/bootstrap.min.css", "r");
  size_t sent = server.streamFile(file, "text/css");  
}

void file_dashboard()
{
  File file = SPIFFS.open("/dashboard.css", "r");
  size_t sent = server.streamFile(file, "text/css");  
}

void file_txtools()
{
  File file = SPIFFS.open("/tx-tools.html", "r");
  size_t sent = server.streamFile(file, "text/html");  
}

void file_datatools()
{
  File file = SPIFFS.open("/data-convert.html", "r");
  size_t sent = server.streamFile(file, "text/html");  
}

void check_TX_Status(){
  String activeTX="";
  if (TXstatus==1) {   
    if (pinHTML!="") {
      String currentPIN=pinHTML;
      activeTX="Brute forcing PIN: "+currentPIN+"<br><a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>";
      currentPIN="";
    }
    else if (dos==1) {
      activeTX="Denial of Service mode active...<br><a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>";
    }
    else {
      activeTX="Transmitting...<br><a href=\"/stoptx\"><button>STOP CURRENT TRANSMISSION</button></a>";
      }
  }
  else {
    activeTX="INACTIVE<br><button>NOTHING TO STOP</button>";
  }
  server.send(200, "text/html", String()+activeTX);
}


//Do It!

///////////////////////////////////////////////////////
void loop()
{
  if (ftpenabled==1){
    ftpSrv.handleFTP();
  }
  server.handleClient();
  httpServer.handleClient();

  if(wg.available()) {
    wg.pause();             // pause Wiegand pin interrupts
    Serial.println("READ CARD");
    LogWiegand(wg);
    wg.clear();             // compulsory to call clear() to enable interrupts for subsequent data
    if (safemode==1) {
      ESP.restart();
    }
  }
}
