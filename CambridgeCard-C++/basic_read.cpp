/*
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//
//  Cambridge Access Card Example
//
//  Created by Peter Birch on 13/08/2013.
//  Copyright (c) 2013 Peter Birch. All rights reserved.
//

#include <iostream>
#include <nfc/nfc.h>
#include <freefare.h>

using namespace std;

// The sector we want to read from
const MifareClassicSectorNumber sector = 2;
// The block within sector 2
const MifareClassicBlockNumber block = mifare_classic_sector_first_block(sector);
// The A key for sector 2, block 0
const MifareClassicKey key = { 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6 }; // <-- CHANGE THIS

int main(int argc, const char * argv[])
{
    // Create an instance of libnfc that we are working with
    nfc_context *context;
    nfc_init(&context);

    if(context == NULL) {
        printf("Unable to init libnfc\n");
        exit(EXIT_FAILURE);
    }

    printf("Using libnfc version %s\n", nfc_version());

    // Get a handle on the NFC reader device
    nfc_device *device = NULL;
    device = nfc_open(context, NULL);
    if (device == NULL) {
        printf("Unable to open NFC device!\n");
        exit(EXIT_FAILURE);
    }

    printf("Opened NFC device\n");

    // Start to look for available access cards
    MifareTag *tags = NULL;
    tags = freefare_get_tags(device);
    if(tags == NULL) {
        printf("Unable to find any NFC tags!\n");
        exit(EXIT_FAILURE);
    }

    // Work through available cards
    for (int i = 0; tags[i]; i++) {
        MifareTag tag = tags[i];

        // Check type is one we are ok working with - Cambridge uses 4k cards
        mifare_tag_type type = freefare_get_tag_type(tag);
        if(type == CLASSIC_1K) printf("Classic 1k card detected!\n");
        else if(type == CLASSIC_4K) printf("Classic 4k card detected!\n");
        else continue;

        // Try to read card
        if(mifare_classic_connect(tag) != 0) {
            printf("Failed to connect to Mifare card!\n");
            continue;
        } else {
            printf("Successfully found Mifare card with %lu sectors\n", mifare_classic_sector_block_count(sector));
        }

        // Try to authenticate against sector
        if(mifare_classic_authenticate(tag, block, key, MFC_KEY_A) != 0) {
            printf("Failed to authenticate against sector!\n");
            continue;
        } else {
            printf("Successfully authenticated against sector\n");
        }

        // Produce a blank block that we are going to fill
        MifareClassicBlock blockdata = {
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        };

        // Read data back from the tag
        mifare_classic_read(tag, block, &blockdata);

        // Print data
        printf("Read Length: %lu\n", sizeof(&blockdata));
        printf("CSRid: %s\n", blockdata);

        // Disconnect from the mifare tag
        mifare_classic_disconnect(tag);
    }

    // Close up
    nfc_close(device);
    device = NULL;

    return 0;
}