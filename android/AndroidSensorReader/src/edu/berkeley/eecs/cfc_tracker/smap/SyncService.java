package edu.berkeley.eecs.cfc_tracker.smap;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

public class SyncService extends Service {
	
    // Storage for an instance of the sync adapter
    private static AddDataAdapter sDataAdapter = null;
    // Object to use as a thread-safe lock
    private static final Object sDataAdapterLock = new Object();
    
    /*
     * Instantiate the sync adapter object.
     */
    @Override
    public void onCreate() {
        /*
         * Create the sync adapter as a singleton.
         * Set the sync adapter as syncable
         * Disallow parallel syncs
         */
    	System.out.println("SyncService.onCreate called");
        synchronized (sDataAdapterLock) {
            if (sDataAdapter == null) {
                sDataAdapter = new AddDataAdapter(getApplicationContext(), true);
            }
        }
    }	

	@Override
	public IBinder onBind(Intent intent) {
		/*
         * Get the object that allows external processes
         * to call onPerformSync(). The object is created
         * in the base class code when the SyncAdapter
         * constructors call super()
         */
		System.out.println("Returning "+sDataAdapter.getSyncAdapterBinder());
        return sDataAdapter.getSyncAdapterBinder();
	}

}
