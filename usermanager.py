# user class for standard accounts
class User:
    def __init__(self, username, password):
        self._username = username          # protected attribute
        self.__password = password       # private attribute (hidden for securely, will have to encrypt later)
        self._knowledge = []               # protected list for knowledge items

    def get_username(self):
        # public method to safely view the protected username
        return self._username

    def check_password(self, pwd):
        # public method to check the private password without exposing it
        return self.__password == pwd

    def add_knowledge(self, item):
        # add a piece of knowledge to this user's protected list
        self._knowledge.append(item)


# admin user class that inherits from user
class AdminUser(User):
    def __init__(self, username, password):
        super().__init__(username, password)
        self.__is_admin = True             # private admin flag

    def remove_user(self, user_list, target_name):
        # loop through the list to find and remove the user usi    `ng their protected username
        for user in user_list:
            if user.get_username() == target_name:
                user_list.remove(user)


# class for a piece of stored information
class KnowledgeItem:
    def __init__(self, title, content):
        self._title = title                # protected title
        self.__content = content           # private encrypted content

    def get_content(self):
        # public method to access private content of any function that ha access to the KnowledgeItem instance
        return self.__content


# class to group multiple users together
class Group:
    def __init__(self, name):
        self._name = name                  # protected group name
        self.__members = []              # private list of members

    def add_member(self, user):
        # add a user to the private members list
        self.__members.append(user)

    def get_members(self):
        # public method to view members
        return self.__members