package edu.berkeley.eecs.cfc_tracker;

import java.io.File;
import java.util.Properties;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.IBinder;
import android.widget.Toast;

public class CommuteTrackerService extends Service implements Runnable, SensorEventListener {
	public static int SLEEP_TIME = 60 * 1000; // 60 seconds = 1 minute
	Thread pollThread = new Thread(this);
	boolean running = false;
	
	/** The file that stores location and accelerometer data */
	File privateFileDir;

	// Value in milliseconds
	public static long MIN_TIME_BW_UPDATES = 60 * 1000L;
	// Value is in meters
	public static float MIN_DISTANCE_CHANGE_FOR_UPDATES = 50;
	// value in microsecs
	private static int ACCEL_READ_DURATION = 10 * 1000;
	
	/** For Location */
	LocationManager locationManager;
    Location location = new Location("plaeholderprovider");
    
    double latitude, longitude;
    
    Sensor accelerometer;
	SensorManager sm;
	
	int batteryPercent;
	int voltage;
	
	double accelerameter_x = 0;
	double accelerameter_y = 0;
	double accelerameter_z = 0;

	@Override
	public IBinder onBind(Intent intent) {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * Quick note on the multi-threading and synchronization here, to write it down for the record.
	 * First, we cannot poll in the onStartCommand function because it is run in the main thread of the
	 * application, and putting a long running loop in here will cause the application to be non-responsive
	 * (I have tested this). So, we launch a poll thread in the start command.
	 * 
	 * Second, all the Thread.stop() methods are currently deprecated because they don't shutdown the thread
	 * cleanly. So we are going to use a boolean variable (running) to control it.
	 * 
	 * But we using this boolean variable without any synchronization! How is this OK!??
	 * 
	 * The answer is two-fold:
	 * a) The thread only ever reads the variable. It is only written by the main thread in onStartCommand() and onDestroy.
	 * b) In both write locations, the variable is written without any checks. So there are no dependencies to worry about.
	 * c) It is fine for the thread to read a slightly stale value - it will just read to us reading one additional set of
	 *    sensor values.
	 */
	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		System.out.println("CommuteTrackerService.onStartCommand invoked with flags = "+flags+
				" startId = "+startId);
		if (!running) {
			pollThread.start();
			sm = (SensorManager) getSystemService(SENSOR_SERVICE);
	        accelerometer = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER);
			locationManager = (LocationManager) getSystemService(LOCATION_SERVICE);
			setLocation();
			running = true;
			privateFileDir = getFilesDir();
			System.out.println("Writing sensor data to directory "+privateFileDir
					+" whose existence state is "+privateFileDir.exists());
		}
		return START_STICKY;
	}
	
	public void run() {
		// We currently keep polling the sensors until the service is stopped
		System.out.println("Starting the run");
		while(running) {
			try {
				System.out.println("Polling sensors");
				System.out.println("Starting reading accelerometer data");
		        sm.registerListener((SensorEventListener) this, accelerometer, SensorManager.SENSOR_DELAY_NORMAL); 
		        Thread.sleep(ACCEL_READ_DURATION);
		        System.out.println("Stopped reading accelerometer data");
				sm.unregisterListener((SensorEventListener)this);
				Thread.sleep(SLEEP_TIME - ACCEL_READ_DURATION);
				Thread.sleep(SLEEP_TIME);
			}
			catch (InterruptedException e) {
				System.out.println("Polling thread in CFC tracker interrupted while sleeping, restarting polling");
			}
		}
	}
	
	/** Uses GPS services or Network provider to monitor and store location */
	public void setLocation() {
	    try {
	        // getting GPS status
	        boolean isGPSEnabled = locationManager
	                .isProviderEnabled(LocationManager.GPS_PROVIDER);

	        // getting network status
	        boolean isNetworkEnabled = locationManager
	                .isProviderEnabled(LocationManager.NETWORK_PROVIDER);
	        
        	System.out.println("isNetworkEnabled = "+isNetworkEnabled+" && isGPSEnabled = "+isGPSEnabled);

	        if (!isGPSEnabled && !isNetworkEnabled) {
	        	Toast.makeText(this,"GPS and network not enabled, location tracking disabled!",
	        			Toast.LENGTH_LONG).show();
	        } else {
	            if (isNetworkEnabled) {
	                locationManager.requestLocationUpdates(
	                        LocationManager.NETWORK_PROVIDER,
	                        MIN_TIME_BW_UPDATES,
	                        MIN_DISTANCE_CHANGE_FOR_UPDATES, mLocationListener);
	                if (locationManager != null) {
	                    location = locationManager
	                            .getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
	                    if (location != null) {
	                        latitude = location.getLatitude();
	                        longitude = location.getLongitude();
	                    }
	                }
	            }

	            if (isGPSEnabled) {
                    locationManager.requestLocationUpdates(
                            LocationManager.GPS_PROVIDER,
                            MIN_TIME_BW_UPDATES,
                            MIN_DISTANCE_CHANGE_FOR_UPDATES, mLocationListener);
                    if (locationManager != null) {
                        location = locationManager
                                .getLastKnownLocation(LocationManager.GPS_PROVIDER);
                        if (location != null) {
                        	Properties locData = new Properties();
                        	locData.put(Constants.LATITUDE, location.getLatitude());
                            locData.put(Constants.LONGITUDE,location.getLongitude());
                        }
                    }
	            }
	        }

	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
	
	/** Define a LocationListener to listen to updates from locationManager. */
	LocationListener mLocationListener = new LocationListener() {

        @Override
        public void onStatusChanged(String provider, int status, Bundle extras) {}
        @Override
        public void onProviderEnabled(String provider) {}
        @Override
        public void onProviderDisabled(String provider) {}
        @Override
        public void onLocationChanged(Location newLoc) {
        	Properties locData = new Properties();
        	locData.put(Constants.LATITUDE, String.valueOf(newLoc.getLatitude()));
            locData.put(Constants.LONGITUDE, String.valueOf(newLoc.getLongitude()));
            
            /** Writes location to local file. */
            DataUtils.saveData(locData, privateFileDir);
        }
    };
    
    /** Call to monitor battery usage */
    private void getBatteryPercentage() {
		  BroadcastReceiver batteryLevelReceiver = new BroadcastReceiver() {
		         public void onReceive(Context context, Intent intent) {
		             context.unregisterReceiver(this);
		             int currentLevel = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
		             int vol = intent.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1);
		             int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
		             int level = -1;
		             if (currentLevel >= 0 && scale > 0) {
		                 level = (currentLevel * 100) / scale;
		             }
		             batteryPercent = level;
		             voltage = vol;
		         }
		     }; 
		     IntentFilter batteryLevelFilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
		     registerReceiver(batteryLevelReceiver, batteryLevelFilter);
	}
	
	public void onSensorChanged(SensorEvent event){
		accelerameter_x = event.values[0];
		accelerameter_y = event.values[1];
		accelerameter_z = event.values[2]; 
		Properties accelData = new Properties();
		accelData.put(Constants.ACCELERATOR_X, String.valueOf(event.values[0]));
		accelData.put(Constants.ACCELERATOR_Y, String.valueOf(event.values[1]));
		accelData.put(Constants.ACCELERATOR_Z, String.valueOf(event.values[2]));
		
		/** Writes accelerometer data to local file. */
		DataUtils.saveData(accelData, privateFileDir);
		System.out.println("X: " + accelerameter_x + "Y: "+ accelerameter_y + "Z: " + accelerameter_z + "Battery: " + batteryPercent);
  }
	
	@Override
	public void onDestroy() {
		running = false;
		System.out.println("CommuteTrackerService.onDestroy invoked");
		sm.unregisterListener((SensorEventListener)this);
		locationManager.removeUpdates(mLocationListener);
	}

	@Override
	public void onAccuracyChanged(Sensor arg0, int arg1) {
		// TODO Auto-generated method stub
	}
}
