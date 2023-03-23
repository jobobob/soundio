#include <Arduino.h>
#include <SPI.h>
#include <MFRC522.h>
#include <HTTPClient.h>
#include "SpotifyClient.h"
#include "settings.h"


#define RST_PIN         27          // Configurable, see typical pin layout above
#define SS_PIN          5         // Configurable, see typical pin layout above
 
#define MISO_PIN  19 
#define MOSI_PIN  23 
#define SCK_PIN   18 

MFRC522 mfrc522(SS_PIN, RST_PIN);  // Create MFRC522 instance
//SPIClass spi(HSPI);
byte const BUFFERSiZE = 176;
MFRC522::MIFARE_Key key;
bool successRead;
byte sector = 1;
byte blockAddr = 4;
byte trailerBlock = 7;
MFRC522::StatusCode status;

SpotifyClient spotify = SpotifyClient(clientId, clientSecret, deviceName, refreshToken);

void connectWifi()
{
  WiFi.begin(ssid, pass);
  Serial.println("");

  // Wait for connection
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());
}

void setup() {
	Serial.begin(115200);		// Initialize serial communications with the PC
	while (!Serial);        // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
	pinMode(SS_PIN, OUTPUT);
    SPI.begin();//SCK_PIN, MISO_PIN, MOSI_PIN, SS_PIN);
	mfrc522.PCD_Init();		// Init MFRC522
	delay(200);				// Optional delay. Some board do need more time after init to be ready, see Readme
	mfrc522.PCD_DumpVersionToSerial();	// Show details of PCD - MFRC522 Card Reader details
	Serial.println(F("Scan PICC to see UID, SAK, type, and data blocks..."));

	for (byte i = 0; i < 6; i++) {
    	key.keyByte[i] = 0xFF;
  }

  connectWifi();

  spotify.FetchToken();
  spotify.GetDevices();
}

void playSpotifyUri(String context_uri)
{
  int code = spotify.Play(context_uri);
  switch (code)
  {
    case 404:
    {
      // device id changed, get new one
      spotify.GetDevices();
      spotify.Play(context_uri);
      spotify.Shuffle();
      break;
    }
    case 401:
    {
      // auth token expired, get new one
      spotify.FetchToken();
      spotify.Play(context_uri);
      spotify.Shuffle();
      break;
    }
    default:
    {
      spotify.Shuffle();
      break;
    }
  }
}


void readNFCTagData(byte *dataBuffer)
{
  MFRC522::StatusCode status;
  byte byteCount;
  byte buffer[18];
  byte x = 0;

  int totalBytesRead = 0;

  // reset the dataBuffer
  for (byte i = 0; i < BUFFERSiZE; i++)
  {
    dataBuffer[i] = 0;
  }

  for (byte page = 0; page < BUFFERSiZE / 4; page += 4)
  {
    // Read pages
    byteCount = sizeof(buffer);
    status = mfrc522.MIFARE_Read(page, buffer, &byteCount);
    if (status == mfrc522.STATUS_OK)
    {
      totalBytesRead += byteCount - 2;

      for (byte i = 0; i < byteCount - 2; i++)
      {
        dataBuffer[x++] = buffer[i]; // add data output buffer
      }
    }
    else
    {
      break;
    }
  }
}


/*
  Parse the Spotify link from the NFC tag data
  The first 28 bytes from the tag is a header info for the tag
  Spotify link starts at position 29


  Parse a link
  open.spotify.com/album/3JfSxDfmwS5OeHPwLSkrfr
  open.spotify.com/playlist/69pYSDt6QWuBMtIWSZ8uQb
  open.spotify.com/artist/53XhwfbYqKCa1cC15pYq2q


  Return a uri
  spotify:album:3JfSxDfmwS5OeHPwLSkrfr
  spotify:playlist:69pYSDt6QWuBMtIWSZ8uQb
  spotify:artist:53XhwfbYqKCa1cC15pYq2q

*/

String parseNFCTagData(byte *dataBuffer)
{
  // first 28 bytes is header info
  // data ends with 0xFE
  String retVal = "spotify:";
  for (int i = 28 + 17; i < BUFFERSiZE; i++)
  {
    if (dataBuffer[i] == 0xFE || dataBuffer[i] == 0x00)
    {
      break;
    }
    if (dataBuffer[i] == '/')
    {
      retVal += ':';
    }
    else
    {
      retVal += (char)dataBuffer[i];
    }
  }
  return retVal;
}

/**
  Helper routine to dump a byte array as hex values to Serial.
*/
void dump_byte_array(byte * buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}

bool readCard() {
  //nfcTagObject tempCard;
  // Show some details of the PICC (that is: the tag/card)
  Serial.print(F("Card UID:"));
  //dumpSomeInfo();
  dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  byte buffer[18];
  byte size = sizeof(buffer);

  // Authenticate using key A
  if ((piccType == MFRC522::PICC_TYPE_MIFARE_MINI ) ||
      (piccType == MFRC522::PICC_TYPE_MIFARE_1K ) ||
      (piccType == MFRC522::PICC_TYPE_MIFARE_4K ))
  {
    Serial.println(F("Authenticating Classic using key A..."));
    status = mfrc522.PCD_Authenticate(
               MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
  }
  else if (piccType == MFRC522::PICC_TYPE_MIFARE_UL )
  {
    byte pACK[] = {0, 0}; //16 bit PassWord ACK returned by the tempCard

    // Authenticate using key A
    Serial.println(F("Authenticating MIFARE UL..."));
    status = mfrc522.PCD_NTAG216_AUTH(key.keyByte, pACK);
  }

  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return false;
  }

  // Show the whole sector as it currently is
  // Serial.println(F("Current data in sector:"));
  // mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
  // Serial.println();

  // Read data from the block
  if ((piccType == MFRC522::PICC_TYPE_MIFARE_MINI ) ||
      (piccType == MFRC522::PICC_TYPE_MIFARE_1K ) ||
      (piccType == MFRC522::PICC_TYPE_MIFARE_4K ) )
  {
    Serial.print(F("Reading data from block "));
    Serial.print(blockAddr);
    Serial.println(F(" ..."));
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Read() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
    }
  }
  else if (piccType == MFRC522::PICC_TYPE_MIFARE_UL )
  {
    byte buffer2[18];
    byte size2 = sizeof(buffer2);
    byte length;

    /*read page 4, 18 bytes, but check/ignore the first 9 bytes. Actual payload starts at byte 10
    Expectation:
      0x03 : NDEF record
      0xYZ : YZ = length of the actual data
      0xD1 : Record Header mark
      0x01 : type length
      0x?? : unsure, ignore for now
      0x54 : Text message, would be different for URI etc., for now we rely on 0x54
      0x02 : UTF-8 encoding and length of language identifier, we assume 2 for the length, but actually ignore it
      0x?? : Langcode b1
      0x?? : Langcode b2
    */
    status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(4, buffer2, &size2);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Read_1() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return false;
    }

    if (buffer2[0] != 0x03) {
      Serial.println(F("expected NDEF record 0x03, return"));
    }
    if (buffer2[2] != 0xD1) {
      Serial.println(F("expected header mark 0xD1, return"));
    }
    if (buffer2[3] != 0x01) {
      Serial.println(F("expected type length 0x01, return"));
    }
    length = buffer2[1] - 7; //minus the header stuff

    Serial.print(F("Length of content to expect:"));
    Serial.println(length);

    byte dataBuffer[length];
    memcpy(dataBuffer, buffer2 + 9, 7);
    dump_byte_array(dataBuffer, 7);
    Serial.println();
    int index = 7;
    int chomp = min(16, length - index);

    for (int i = 0x08; i < 0x0F; i+=4) {
      status = (MFRC522::StatusCode)mfrc522.MIFARE_Read(i, buffer2, &size2);
      if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read_1() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return false;
      }
      Serial.println(F("raw"));
      dump_byte_array(buffer2, 16);
      if(index + chomp > length)
        chomp = length - index;
      memcpy(dataBuffer+index, buffer2, chomp);
      
      Serial.println();
      Serial.println("rolling");
      dump_byte_array(dataBuffer, index+16);
      
      if(chomp < 16)
        break;
      index += chomp;
    }

    Serial.println();
    Serial.println("resulting buffer");
    dump_byte_array(dataBuffer, length);

    String uri = String(dataBuffer, length);
    playSpotifyUri(uri);
  }
  return true;
}

void readNFCTag()
{
  if (mfrc522.PICC_ReadCardSerial())
  {
    byte dataBuffer[BUFFERSiZE];
    readNFCTagData(dataBuffer);
    mfrc522.PICC_HaltA();

    //hexDump(dataBuffer);
    Serial.print("Read NFC tag: ");
    String context_uri = parseNFCTagData(dataBuffer);
    Serial.println(context_uri);
    //playSpotifyUri(context_uri);
  }
}


void loop() {
	// Serial.println("Hello world!");
    //delay(1000);
	
	// Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
	if (mfrc522.PICC_IsNewCardPresent())
	{
		if (!mfrc522.PICC_ReadCardSerial())
    		return;
		Serial.println("NFC tag present");
		readCard();

		mfrc522.PICC_HaltA();
  	mfrc522.PCD_StopCrypto1();
	}

	//if (mfrc522.PICC_ReadCardSerial()) { // NUID has been readed
     // dumpSomeInfo();
	  //readNFCTag();
      //mfrc522.PICC_HaltA(); // halt PICC
      //mfrc522.PCD_StopCrypto1(); // stop encryption on PCD
    //}
}