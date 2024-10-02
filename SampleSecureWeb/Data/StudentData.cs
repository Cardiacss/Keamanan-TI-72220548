using System;
using System.Data.Common;
using System.Diagnostics;
using SampleSecureWeb.Models;

namespace SampleSecureWeb.Data;

public class StudentData : IStudent
{
    private readonly ApplicationDbContexts _db;

    public StudentData(ApplicationDbContexts db)
    {
        _db = db;
    }
    public Student AddStudent(Student student)
    {
        try
        {
            _db.Students.Add(student);
            _db.SaveChanges();  
            return student; 
        }
        catch (System.Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public Student DeleteStudent(string Nim)
    {
        throw new NotImplementedException();
    }

    public IEnumerable<Student> GetStudents()
    {
        var student = _db.Students.OrderBy(s => s.FullName);
        return student;
    }

    public Student GetStudent(string Nim)
    {
        throw new NotImplementedException();
    }

    public Student UpdateStudent(Student student)
    {
        throw new NotImplementedException();
    }

}