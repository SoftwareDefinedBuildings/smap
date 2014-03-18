package edu.berkeley.eecs.cfc_tracker;

import android.os.Bundle;
import android.accounts.Account;
import android.accounts.AccountManager;
import android.app.Activity;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.view.Menu;
import android.view.View;

public class MainActivity extends Activity {
	boolean initDone = false;
    // The authority for the sync adapter's content provider
    public static final String AUTHORITY = "edu.berkeley.eecs.cfc_tracker.provider";
    // An account type, in the form of a domain name
    public static final String ACCOUNT_TYPE = "YOUR_BMS_SERVER_HERE";
    // The account name
    public static final String ACCOUNT = "dummy_account";
    
    private static final long SYNC_INTERVAL = 30 * 60L; // 30 mins

    Account mAccount;
    // Our ContentResolver is actually a dummy - does this matter?
    ContentResolver mResolver;
    
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		
		System.out.println("MainActivity.onCreate called");
		setContentView(R.layout.activity_main);
		if (!initDone) {
			AlarmHandler.setupAlarms(this);
			initDone = true;
		}

		// TODO: Determine whether this is the right place to create this.  This
		// will work for now because we launch the activity on reboot, but we need
		// to figure out our UI story and see if this will always be true. If not,
		// we need to move it (and the alarm setup) to some other location.
		mAccount = GetOrCreateSyncAccount(this);
		System.out.println("mAccount = "+mAccount);
	    // Get the content resolver for your app
	    mResolver = getContentResolver();
	    // Turn on automatic syncing for the default account and authority
	    ContentResolver.setSyncAutomatically(mAccount, AUTHORITY, true);
	    /*
	     * This is the SECOND time that the online tutorial has been bogus and caused me to waste
	     * hours in getting the framework working. Contrary to the code in:
	     * https://developer.android.com/training/sync-adapters/running-sync-adapter.html
	     * it turns out that the last argument to addPeriodicSync is in SECONDS, not MILLISECONDS.
	     * So when I had 15 * 1000L, it didn't run in any visible time.
	     * Changing it to 15 causes it to run at a frequency that is visible.
	     * Of course, we don't really want to run this at this frequency in the real world.
	     * Need to tweak this. Make it a configurable option?
	     * 
	     * Also, note that sometimes, the networking in the emulator gets disconnected,
	     * and that might be the cause for the sync not happening as well.
	     * 
	     * TODO: Test to see whether the manual sync works even when the network is detected as down
	     * (need to wait for the emulator to get into this bad state again)
	     */
	    ContentResolver.addPeriodicSync(mAccount, AUTHORITY, new Bundle(), SYNC_INTERVAL);
	    System.out.println("Setting the resolver to sync automatically");
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}
	
	public void startService(View view) {
		System.out.println("MainActivity sending start service !!");
		// NOTE: new Intent(this, MainActivity.class) here instead FAILS
		Intent intent = new Intent();
		// intent.setAction("android.intent.action.AIRPLANE_MODE");
		// NOTE: you HAVE to set the action here. Skipping the action here,
		// and skipping the intentFilter in the android manifest FAILS 
		intent.setAction(getString(R.string.startAtDropoff));
		sendBroadcast(intent);
	}
	
	public void stopService(View view) {
		System.out.println("MainActivity sending stop service !!");
		Intent intent = new Intent();
		intent.setAction(getString(R.string.stopAtDropoff));
		sendBroadcast(intent);
	}
	
	public void forceSync(View view) {
		System.out.println("MainActivity forcing sync");
		ContentResolver.requestSync(mAccount, AUTHORITY, new Bundle());
	}
	
	@Override
	protected void onStart() {
		super.onStart();
		System.out.println("MainActivity.onStart called");
	}

	@Override
	protected void onStop() {
		super.onStop();
		System.out.println("MainActivity.onStop called");
	}
	
	@Override
	protected void onDestroy() {
		super.onDestroy();
		System.out.println("MainActivity.onDestroy called");
	}

  public static Account GetOrCreateSyncAccount(Context context) {
    // Get an instance of the Android account manager
    AccountManager accountManager =
            (AccountManager) context.getSystemService(
                    ACCOUNT_SERVICE);
    Account[] existingAccounts = accountManager.getAccountsByType(ACCOUNT_TYPE);
    assert(existingAccounts.length <= 1);
    if (existingAccounts.length == 1) {
    	return existingAccounts[0];
    }
	  
	// Create the account type and default account
	Account newAccount = new Account(ACCOUNT, ACCOUNT_TYPE);	  
    /*
     * Add the account and account type, no password or user data
     * If successful, return the Account object, otherwise report an error.
     */
    if (accountManager.addAccountExplicitly(newAccount, null, null)) {
      return newAccount;
    } else {
      System.err.println("Unable to create a dummy account to sync with!");
      return null;
    }
  }
}
