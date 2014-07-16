package edu.berkeley.eecs.cfc_tracker;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/*
 * Class that allows us to re-register the alarms when the phone is rebooted.
 */
public class BootReceiver extends BroadcastReceiver {

	@Override
	public void onReceive(Context ctx, Intent intent) {
        if (intent.getAction().equals("android.intent.action.BOOT_COMPLETED")) {
        	System.out.println("BootReceiver.onReceive called");
            Intent i = new Intent(ctx, MainActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            System.out.println("Starting activity in boot receiver");
            ctx.startActivity(i);
        }
	}
}
