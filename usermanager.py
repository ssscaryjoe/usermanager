import getpass
import json
import os
import subprocess


def has_admin_privileges():
    # check for Administrator on Windows or root on other supported systems
    if os.name == "nt":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return False


# user class for standard accounts
class User:
    def __init__(self, username, password):
        self._username = username  # protected attribute
        self.__password = password  # private attribute, stored as plain text
        self._knowledge = []  # protected list for knowledge items

    def get_username(self):
        # public method to safely view the protected username
        return self._username

    def check_password(self, pwd):
        # public method to check the private password without exposing it
        return self.__password == pwd

    def add_knowledge(self, item):
        # add a piece of knowledge to this user's protected list
        self._knowledge.append(item)

    def get_knowledge(self):
        # public method to view this user's knowledge items
        return list(self._knowledge)

    def is_admin(self):
        # public method to check this user's account type
        return False

    def to_record(self):
        # prepare this user's data for the protected storage file
        knowledge = []
        for item in self._knowledge:
            knowledge.append(item.to_record())
        return {
            "password": self.__password,
            "admin": self.is_admin(),
            "knowledge": knowledge
        }


# admin user class that inherits from user
class AdminUser(User):
    def __init__(self, username, password):
        super().__init__(username, password)
        self.__is_admin = True  # private admin flag

    def is_admin(self):
        # public method to check this user's account type
        return self.__is_admin

    def remove_user(self, user_table, target_name):
        # remove a user from the hash table using their username
        if target_name in user_table and target_name != self.get_username():
            del user_table[target_name]
            return True
        return False


# class for a piece of stored information
class KnowledgeItem:
    def __init__(self, title, content):
        self._title = title  # protected title
        self.__content = content  # private content

    def get_content(self):
        # public method to access private content
        return self.__content

    def get_title(self):
        # public method to view the knowledge title
        return self._title

    def to_record(self):
        # save this knowledge item's content
        return {"title": self._title, "content": self.__content}


# class to group multiple users together
class Group:
    def __init__(self, name):
        self._name = name  # protected group name
        self.__members = []  # private list of members

    def add_member(self, user):
        # add a user to the private members list
        if user not in self.__members:
            self.__members.append(user)

    def get_members(self):
        # public method to view members
        return list(self.__members)

    def remove_member(self, username):
        # remove a user from the group by username
        self.__members = [
            user for user in self.__members
            if user.get_username() != username
        ]

    def get_name(self):
        # public method to view the group name
        return self._name


class UserManager:
    def __init__(self, storage_path):
        if not has_admin_privileges():
            raise PermissionError("Run this program as Administrator or root.")
        self._storage_path = storage_path
        self.users = {}  # hash table of usernames and User objects
        self.groups = {}  # hash table of group names and Group objects
        self._prepare_storage()
        self._load_users()

    def _prepare_storage(self):
        # create the private directory before creating the user file
        directory = os.path.dirname(self._storage_path)
        os.makedirs(directory, exist_ok=True)
        if os.name == "nt":
            self._set_windows_permissions(directory, True)
            if os.path.exists(self._storage_path):
                self._set_windows_permissions(self._storage_path, False)
        else:
            os.chown(directory, 0, 0)
            os.chmod(directory, 0o700)
            if os.path.exists(self._storage_path):
                os.chown(self._storage_path, 0, 0)
                os.chmod(self._storage_path, 0o600)

    def _set_windows_permissions(self, path, is_directory):
        # restrict storage to Windows Administrators and SYSTEM
        permission = "F"
        if is_directory:
            permission = "(OI)(CI)F"
        subprocess.run(
            ["icacls", path, "/setowner", "*S-1-5-32-544"],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            [
                "icacls", path, "/inheritance:r", "/grant:r",
                "*S-1-5-18:" + permission,
                "*S-1-5-32-544:" + permission
            ],
            check=True,
            capture_output=True,
            text=True
        )

    def _load_users(self):
        # load saved users into the hash table
        if not os.path.exists(self._storage_path):
            return
        with open(self._storage_path, "r", encoding="utf-8") as file:
            data = json.load(file)
        for username, record in data.get("users", {}).items():
            user_class = AdminUser if record.get("admin", False) else User
            user = user_class(username, record["password"])
            for item_record in record.get("knowledge", []):
                item = KnowledgeItem(item_record["title"], item_record["content"])
                user.add_knowledge(item)
            self.users[username] = user
        for group_name, member_names in data.get("groups", {}).items():
            group = Group(group_name)
            for username in member_names:
                if username in self.users:
                    group.add_member(self.users[username])
            self.groups[group_name] = group

    def _save_users(self):
        # save the hash table to the protected text file
        data = {"users": {}, "groups": {}}
        for username, user in self.users.items():
            data["users"][username] = user.to_record()
        for name, group in self.groups.items():
            member_names = []
            for user in group.get_members():
                member_names.append(user.get_username())
            data["groups"][name] = member_names
        with open(self._storage_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        if os.name == "nt":
            self._set_windows_permissions(self._storage_path, False)
        else:
            os.chown(self._storage_path, 0, 0)
            os.chmod(self._storage_path, 0o600)

    def add_user(self, username, password, is_admin=False):
        # add a user to the hash table and save the updated data
        username = username.strip()
        if not username or not password:
            raise ValueError("Username and password must not be empty.")
        if username in self.users:
            return False
        user_class = AdminUser if is_admin else User
        self.users[username] = user_class(username, password)
        self._save_users()
        return True

    def authenticate(self, username, password):
        # check the username and password without exposing the password
        user = self.users.get(username)
        if user and user.check_password(password):
            return user
        return None

    def remove_user(self, admin, target_name):
        # allow only an administrator to remove another user
        if not admin.is_admin():
            return False
        removed = admin.remove_user(self.users, target_name)
        if removed:
            for group in self.groups.values():
                group.remove_member(target_name)
            self._save_users()
        return removed

    def add_group(self, name):
        # add a group to the group hash table and save it
        name = name.strip()
        if not name or name in self.groups:
            return False
        self.groups[name] = Group(name)
        self._save_users()
        return True

    def add_group_member(self, group_name, username):
        # add an existing user to a group and save the change
        if group_name not in self.groups or username not in self.users:
            return False
        self.groups[group_name].add_member(self.users[username])
        self._save_users()
        return True

    def save(self):
        # save changes made to a user's knowledge
        self._save_users()


def add_knowledge_menu(user, manager):
    # let a logged-in user add or view their knowledge
    while True:
        print("\n1. Add knowledge")
        print("2. View knowledge")
        print("3. Log out")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            title = input("Knowledge title: ").strip()
            content = input("Knowledge content: ")
            if not title or not content:
                print("Title and content must not be empty.")
            else:
                item = KnowledgeItem(title, content)
                user.add_knowledge(item)
                manager.save()
                print("Knowledge saved.")
        elif choice == "2":
            for item in user.get_knowledge():
                print("\n" + item.get_title() + ":")
                print(item.get_content())
            if not user.get_knowledge():
                print("No knowledge has been saved yet.")
        elif choice == "3":
            break
        else:
            print("Choose 1, 2, or 3.")


def admin_menu(admin, manager):
    # let an administrator manage user accounts
    while True:
        print("\n1. List users")
        print("2. Add user")
        print("3. Remove user")
        print("4. List groups")
        print("5. Create group")
        print("6. Add user to group")
        print("7. Log out")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            for username in sorted(manager.users):
                role = "admin" if manager.users[username].is_admin() else "user"
                print(username + " (" + role + ")")
        elif choice == "2":
            username = input("New username: ").strip()
            password = getpass.getpass("New password: ")
            if not username or not password:
                print("Username and password must not be empty.")
            elif manager.add_user(username, password):
                print("User added.")
            else:
                print("That username already exists.")
        elif choice == "3":
            target_name = input("Username to remove: ").strip()
            if manager.remove_user(admin, target_name):
                print("User removed.")
            else:
                print("User not found or you cannot remove your own account.")
        elif choice == "4":
            for name in sorted(manager.groups):
                member_names = []
                for user in manager.groups[name].get_members():
                    member_names.append(user.get_username())
                print(name + ": " + ", ".join(member_names))
            if not manager.groups:
                print("No groups have been created.")
        elif choice == "5":
            name = input("New group name: ").strip()
            if manager.add_group(name):
                print("Group created.")
            else:
                print("Group name must be new and not empty.")
        elif choice == "6":
            name = input("Group name: ").strip()
            username = input("Username to add: ").strip()
            if manager.add_group_member(name, username):
                print("User added to group.")
            else:
                print("Group or user not found.")
        elif choice == "7":
            break
        else:
            print("Choose 1, 2, 3, 4, 5, 6, or 7.")


def main():
    # start the user manager and keep showing the main menu
    if not has_admin_privileges():
        print("Run this program as Administrator or root.")
        return
    folder = os.path.dirname(os.path.abspath(__file__))
    storage_path = os.path.join(folder, "private_folder", "passwords.txt")
    manager = UserManager(storage_path)

    if not manager.users:
        print("Create the initial administrator account.")
        username = ""
        while not username:
            username = input("Administrator username: ").strip()
            if not username:
                print("Username must not be empty.")
        while True:
            password = getpass.getpass("Administrator password: ")
            confirmation = getpass.getpass("Confirm password: ")
            if password and password == confirmation:
                break
            print("Passwords must match and must not be empty.")
        manager.add_user(username, password, is_admin=True)
        print("Administrator account created.")

    while True:
        print("\n1. Log in")
        print("2. Quit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            user = manager.authenticate(username, password)
            if user is None:
                print("Username or password is incorrect.")
            elif user.is_admin():
                admin_menu(user, manager)
            else:
                add_knowledge_menu(user, manager)
        elif choice == "2":
            print("Goodbye.")
            break
        else:
            print("Choose 1 or 2.")


if __name__ == "__main__":
    main()