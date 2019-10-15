# Detailed Install Steps
The steps below for each section provide a step-by-step method to install or configure.

## Install the ESP8266 Board Libraries
Currently I recommend installing the Arduino Core 2.4.2. I will update the code to work with the latest core, however currently it does not seem to function properly.

1. Open the Arduino IDE.

2. Open the **File** menu, then **Preferences**.

3. In the textbox nect to **Additional Boards Manager URLs** paste:

https://arduino.esp8266.com/stable/package_esp8266com_index.json

4. Click **OK**.

5. Open the **Tools** menu, **Board: "xyz"**, **Boards Manager...**.

6. Wait for the platforms index to download, then type "ESP8266".

7. Click the **esp8266 by ESP8266 Community**. Then in the bottom left corner open the **Select version** dropdown and select **2.4.2** then click **Install**.

Done.

## Installing Libraries