package edu.berkeley.eecs.cfc_tracker;

public final class Constants {
	public static String LONGITUDE = "longitude";
	public static String LATITUDE = "latitude";
	public static String ACCELERATOR_X = "ax";
	public static String ACCELERATOR_Y = "ay";
	public static String ACCELERATOR_Z = "az";
	public static String BATTERY_LEVEL = "battery_level";
	public static String ACTIVITY_TYPE = "activity_type";
	public static String ACTIVITY_CONFIDENCE = "activity_confidence";
	
	public static String[] sensors = {LONGITUDE,
									  LATITUDE,
									  ACCELERATOR_X,
									  ACCELERATOR_Y,
									  ACCELERATOR_Z,
									  BATTERY_LEVEL,
									  ACTIVITY_TYPE,
									  ACTIVITY_CONFIDENCE};
}
