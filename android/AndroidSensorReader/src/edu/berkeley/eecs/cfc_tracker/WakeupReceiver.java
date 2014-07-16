package edu.berkeley.eecs.cfc_tracker;

import android.app.NotificationManager;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.support.v4.app.NotificationCompat;

public class WakeupReceiver extends BroadcastReceiver {
	public static int STARTED_MONITORING = 42;
	public static int STOPPED_MONITORING = 43;
	
	@Override
	public void onReceive(Context ctxt, Intent intent) {
		System.out.println("Received broadcast message "+intent);
		if ((intent.getAction().equals(ctxt.getString(R.string.startAtDropoff)) ||
				intent.getAction().equals(ctxt.getString(R.string.startAtPickup)))) {
			createNotification(ctxt, ctxt.getString(R.string.startedMonitoring));
	        // Create a new intent here for the CommuteTrackerService so that it will be delivered correctly
	        Intent serviceStartIntent = new Intent(ctxt, CommuteTrackerService.class);
	        serviceStartIntent.setAction(intent.getAction());
	        ctxt.startService(serviceStartIntent);
		} else {
			createNotification(ctxt, ctxt.getString(R.string.stoppedMonitoring));
			assert(intent.getAction() == ctxt.getString(R.string.stopAtDropoff) ||
					intent.getAction() == ctxt.getString(R.string.stopAtPickup));
			System.out.println("About to stop service");
            //Stop CommuteTrackerService intent
	        Intent serviceStopIntent = new Intent(ctxt, CommuteTrackerService.class);
	        serviceStopIntent.setAction(intent.getAction());
	        ctxt.stopService(serviceStopIntent);
		}
	}
	
	public void createNotification(Context context, String message) {
		NotificationCompat.Builder builder = new NotificationCompat.Builder(context);
		builder.setSmallIcon(R.drawable.ic_launcher);
		builder.setContentTitle(context.getString(R.string.app_name));
		builder.setContentText(message);
		
		/*
		 * This is a bit of magic voodoo. The tutorial on launching the activity actually uses a stackbuilder
		 * to create a fake stack for the new activity. However, it looks like the stackbuilder
		 * is only available in more recent versions of the API. So I use the version for a special activity PendingIntent
		 * (since our app currently has only one activity) which resolves that issue.
		 * This also appears to work, at least in the emulator.
		 * 
		 * TODO: Decide what level API we want to support, and whether we want a more comprehensive activity.
		 */
		Intent activityIntent = new Intent(context, MainActivity.class);
		activityIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		
		PendingIntent activityPendingIntent = PendingIntent.getActivity(context, 0,
				activityIntent, PendingIntent.FLAG_UPDATE_CURRENT);
		builder.setContentIntent(activityPendingIntent);		
		
		NotificationManager nMgr =
				(NotificationManager)context.getSystemService(Context.NOTIFICATION_SERVICE);
		
		if (message.equals(context.getString(R.string.startedMonitoring))) {
			System.out.println("Generating start notify with id "+STARTED_MONITORING);
			nMgr.notify(STARTED_MONITORING, builder.build());
		} else {
			System.out.println("Generating stop notify with id "+STOPPED_MONITORING);
			nMgr.notify(STOPPED_MONITORING, builder.build());
		}
	}
	
	//TODO: If implementing Activity Recognition Services - Implement servicesConnected() and error dialog framework for Google Play connection issues.
}
