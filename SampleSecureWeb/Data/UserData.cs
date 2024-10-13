using System;
using SampleSecureWeb.Models;
using SQLitePCL;
using bc = BCrypt.Net.BCrypt;

namespace SampleSecureWeb.Data;

public class UserData : IUser
{
    private readonly ApplicationDbContexts _db;

    public UserData(ApplicationDbContexts db)
    {
        _db = db;
    }
    public User login(User user)
    {
        var _user = _db.Users.FirstOrDefault(u => u.Username == user.Username);
        if (_user == null)
        {
            throw  new Exception("User Not Found");
        }
        if(!BCrypt.Net.BCrypt.Verify(user.Password, _user.Password))
        {
            throw new Exception("Password Is Incorrect");
        }
        return _user;
    }

    public User registration(User user)
    {
        try
        {
            user.Password = BCrypt.Net.BCrypt.HashPassword  (user.Password);
            _db.Users.Add(user);
            _db.SaveChanges();
            return user;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public void UpdatePassword(User user)
{
    var existingUser = _db.Users.FirstOrDefault(u => u.Username == user.Username);
    if (existingUser != null)
    {
        existingUser.Password = user.Password;
        _db.SaveChanges();
    }
    else
    {
        throw new Exception("User not found");
    }
}
}

