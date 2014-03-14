/*
 * For this app we are using the standard android sync mechanism so that we can upload our data in a relatively power-efficient fashion
 * while without having to check for network connectivity and so on. On the other hand, we don't need the Content Provider at this point:
 * none of our data is shared with other apps, and we don't necessarily want to upload the data as soon as it is generated. So we implement
 * a dummy Content Provider at this point to keep the code easier and revisit it later once we have some data on power consumption, etc.
 * 
 * The stub methods return the values from the android tutorial:
 * https://developer.android.com/training/sync-adapters/creating-stub-provider.html
 */

package edu.berkeley.eecs.cfc_tracker.smap;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;

public class StubContentProvider extends ContentProvider {

	@Override
	public int delete(Uri uri, String selection, String[] selectionArgs) {
		System.out.println("StubContentProvider.delete() called");
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getType(Uri uri) {
		System.out.println("StubContentProvider.getType() called");
		return new String();
	}

	@Override
	public Uri insert(Uri uri, ContentValues values) {
		System.out.println("StubContentProvider.insert() called");
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean onCreate() {
		System.out.println("StubContentProvider.onCreate() called");
		return true;
	}

	@Override
	public Cursor query(Uri uri, String[] projection, String selection,
			String[] selectionArgs, String sortOrder) {
		System.out.println("StubContentProvider.query() called");
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int update(Uri uri, ContentValues values, String selection,
			String[] selectionArgs) {
		System.out.println("StubContentProvider.update() called");
		// TODO Auto-generated method stub
		return 0;
	}

}
