package edu.berkeley.eecs.cfc_tracker;

import java.util.Calendar;

import android.app.Activity;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Intent;

public class AlarmHandler {
    // This value is defined and consumed by app code, so any value will work.
    // There's no significance to this sample using 0.
    public static final int REQUEST_CODE = 0;
    public static final String START_MONITORING = "edu.berkeley.eecs.cfc_tracker.startMonitoring";
    public static final String STOP_MONITORING = "edu.berkeley.eecs.cfc_tracker.stopMonitoring";
    
	public static void setupAlarms(Activity activity) {
        setupAlarm(activity, 7, 30, START_MONITORING+"_dropoff");
        setupAlarm(activity, 8, 45, STOP_MONITORING+"_dropoff");
        setupAlarm(activity, 13, 30, START_MONITORING+"_pickup");
        setupAlarm(activity, 16, 00, STOP_MONITORING+"_pickup");
	}
	
	private static void setupAlarm(Activity activity, int hour, int minute, String intentAction) {
        // BEGIN_INCLUDE (intent_fired_by_alarm)
        /* First create an intent for the alarm to activate.
		 * Note that since we want this alarm to work even if the task has been closed
		 * (by the user pressing the back button, for example). Creating a no-arg intent,
		 * instead of passing in a context and an activity class, and setting an action
		 * that the broadcast receiver can listen on are both critical to making this work.
		 */
		Intent intent = new Intent();
        intent.setAction(intentAction);
        // END_INCLUDE (intent_fired_by_alarm)
        
        // BEGIN_INCLUDE (pending_intent_for_alarm)
        /* Because the intent must be fired by a system service from outside the application,
         * it's necessary to wrap it in a PendingIntent.  Providing a different process with
         * a PendingIntent gives that other process permission to fire the intent that this
         * application has created. We use "getBroadcast" since we don't know that the activity
         * is currently running
         */
        PendingIntent pendingIntent = PendingIntent.getBroadcast(activity, REQUEST_CODE, intent, 0);
        AlarmManager alarmManager = (AlarmManager) activity.getSystemService(Activity.ALARM_SERVICE);

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(System.currentTimeMillis());
        // The alarm needs to fire at around 7:30am for the morning drop-off
        calendar.set(Calendar.HOUR_OF_DAY, hour);
        calendar.set(Calendar.MINUTE, minute);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        
        if (calendar.getTimeInMillis() < System.currentTimeMillis()) {
        	calendar.add(Calendar.DAY_OF_YEAR, 1);
        }
        
        // We are going to use RTC because we want to track motion in two time periods:
        // 7:30 to 8:45, 1:30 to 4:00
        // With setInexactRepeating(), you have to use one of the AlarmManager interval
        // constants--in this case, AlarmManager.INTERVAL_DAY.
        alarmManager.setRepeating(AlarmManager.RTC_WAKEUP, calendar.getTimeInMillis(),
        		AlarmManager.INTERVAL_DAY, pendingIntent);
	}
}
