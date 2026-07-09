from database.db import get_failed_logins, record_failed_login, reset_failed_logins, get_connection

reset_failed_logins("fakeuser")
record_failed_login("fakeuser")
print("Failed 1:", get_failed_logins("fakeuser"))
record_failed_login("fakeuser")
print("Failed 2:", get_failed_logins("fakeuser"))
