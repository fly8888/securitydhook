
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import "sqlite3.h"

int callback(void* data, int n_columns, char** col_values, char** col_names){
  NSMutableArray * results = (NSMutableArray*)data;
  for(int i = 0; i<n_columns; i++){
	NSString * string = [NSString stringWithFormat:@"%s",col_values[i]];
	if(![string hasPrefix:@"com.apple."]&&![string isEqualToString:@"apple"]&&![results containsObject:string])
	{
		[results addObject:string];
	}
  }
  return 0;
}

NSArray * getAllKeychainGroups()
{
	const char * dbPath = "/var/Keychains/keychain-2.db";

    sqlite3 *db;
	char *zErrMsg = 0;
	int rc;
    rc = sqlite3_open(dbPath, &db);
	if(rc != SQLITE_OK)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return nil;
	}

	fprintf(stdout, "Opened database successfully\n");
	NSMutableArray * results = [[NSMutableArray alloc]init];
	rc = sqlite3_exec(db, "SELECT DISTINCT agrp FROM genp", callback, (void*)results, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	rc = sqlite3_exec(db, "SELECT DISTINCT agrp FROM cert", callback, (void*)results, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	rc = sqlite3_exec(db, "SELECT DISTINCT agrp FROM inet", callback, (void*)results, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	rc = sqlite3_exec(db, "SELECT DISTINCT agrp FROM keys", callback, (void*)results, &zErrMsg);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	
	sqlite3_close(db);
	return [results autorelease];
}


extern "C" CFTypeRef SecTaskCopyValueForEntitlement(SecTrustRef task, CFStringRef entitlement, CFErrorRef *error);
%hookf(CFTypeRef, SecTaskCopyValueForEntitlement, SecTrustRef task, CFStringRef entitlement, CFErrorRef *error) {
	CFTypeRef origGroups = %orig;
	if(entitlement&&[(NSString*)entitlement isEqualToString:@"keychain-access-groups"])
	{
		if (@available(iOS 14.0, *))
		{
			if(origGroups &&[(NSArray *)origGroups containsObject:@"*"])
			{
				CFRelease(origGroups);
				NSArray * groups = getAllKeychainGroups();
				return (CFArrayRef)groups;
			}
		}
	}
	return origGroups;
}
