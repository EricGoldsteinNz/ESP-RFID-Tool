/*void data_convert_hex2binHTML (){
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
    
void data_convert_abaHTML (){
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

void data_convert_bin2HexHTML(){
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
}*/

String intTobin (int decimal, int strLen){
  char binCHAR[17];
  String binVal = itoa(decimal,binCHAR,2);
  String paddedBinVal = '0' * strLen - binVal.length();
  return paddedBinVal;
}
