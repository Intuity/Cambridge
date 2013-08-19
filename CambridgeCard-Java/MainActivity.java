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
//  Cambridge Access Card Android Example
//
//  Created by Peter Birch on 13/08/2013.
//  Copyright (c) 2013 Peter Birch. All rights reserved.
//

package com.mayball.nfctest;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;

import java.io.IOException;
import java.nio.ByteBuffer;

public class MainActivity extends Activity {

    IntentFilter filters[];
    String tech_list[][];
    NfcAdapter adapter;
    PendingIntent pending;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // NFC Test Reading Code
        adapter = NfcAdapter.getDefaultAdapter(this);
        pending = PendingIntent.getActivity(this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        IntentFilter filter = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);

        try {
            filter.addDataType("*/*");
        } catch(IntentFilter.MalformedMimeTypeException e) {
            throw new RuntimeException("fail", e);
        }

        filters = new IntentFilter[] { filter, };
        tech_list = new String[][] { new String[] { MifareClassic.class.getName() } };
        Intent newIntent = getIntent();
    }

    @Override
    public void onResume() {
        super.onResume();
        adapter.enableForegroundDispatch(this, pending, filters, tech_list);
    }

    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        resolveIntent(intent);
    }

    @Override
    public void onPause() {
        super.onPause();
        adapter.disableForegroundDispatch(this);
    }

    private void resolveIntent(Intent intent) {
        // Get the action that triggered this Intent
        String action = intent.getAction();

        // Check if we were triggered by discovering a new "tag"
        if(NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
            // Get an instance of the "tag"
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

            // Create an instance of a Mifare tag
            MifareClassic mi_tag = MifareClassic.get(tag);
            byte[] data = "".getBytes();
            boolean gotCSRiD = false;

            // Connect to the card
            try {
                mi_tag.connect();
                boolean auth = false;

                // Check the number of sectors
                int sectors = mi_tag.getSectorCount();
                Log.e("com.mayball.nfctest", "Have " + sectors + " sectors available");

                // Sector 2 contains the CSRiD - check we can read it and then fetch it
                if(sectors > 2) {
                    byte[] sector_2_key = { (byte)0xA1, (byte)0xB2, (byte)0xC3, (byte)0xD4, (byte)0xE5, (byte)0xF6 };
                    auth = mi_tag.authenticateSectorWithKeyA(2, sector_2_key);

                    if(auth) {
                        Log.e("com.mayball.nfctest", "Successfully authenticated sector 2");

                        int blockCount = mi_tag.getBlockCountInSector(2);
                        Log.e("com.mayball.nfctest", blockCount + " Blocks Available");
                        // Read back the blocks
                        for(int i = 8; i < blockCount + 8; i++) { // +8 blocks to get to sector 2
                            byte[] block_data = mi_tag.readBlock(i);
                            ByteBuffer buffer = ByteBuffer.allocate(data.length + block_data.length);
                            buffer.put(data);
                            buffer.put(block_data);
                            buffer.compact();
                            data = buffer.array();
                        }

                        gotCSRiD = true;


                    } else {
                        Log.e("com.mayball.nfctest", "Failed to authenticate sector 2");
                    }
                    auth = false;
                    auth = mi_tag.authenticateSectorWithKeyB(33, MifareClassic.KEY_DEFAULT);
                    if(auth) {
                        Log.e("com.mayball.nfctest", "Success in sector 35");
                        Integer len = "hello there worl".getBytes().length;
                        Log.e("com.mayball.nfctest", len.toString());
                        mi_tag.writeBlock(33*4, "hello there worl".getBytes());
                        Log.e("com.mayball.nfctest", "Success on writing!");
                        byte[] readBack = mi_tag.readBlock(33*4);
                        Log.e("com.mayball.nfctest", "Readback: " + new String(readBack));
                    } else {
                        Log.e("com.mayball.nfctest", "Failure in sector 35");
                    }
                } else {
                    Log.e("com.mayball.nfctest", "Not enough sectors to retrieve CSRiD!");
                }

            } catch(IOException e) {
                Log.e("com.mayball.nfctest", e.getLocalizedMessage());
            }

            if(gotCSRiD) {
                Log.e("com.mayball.nfctest", "Got CSRiD from card: " + new String(data));
                String CSRiD = "";
                for(int i = 0; i < data.length; i++) {
                    Byte sub = data[i];
                    if(sub.intValue() != 0) CSRiD += new String(new byte[] { sub.byteValue() });
                    else break;
                }
                // Print out cutdown CSRiD
                Log.e("com.mayball.nfctest", "Cutdown CSRiD: " + CSRiD);
            }
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }
    
}
