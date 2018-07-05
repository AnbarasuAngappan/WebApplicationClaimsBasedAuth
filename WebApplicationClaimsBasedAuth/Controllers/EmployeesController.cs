using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using WebApplicationClaimsBasedAuth.Models;

namespace WebApplicationClaimsBasedAuth.Controllers
{
    
    [Authorize]
   
    public class EmployeesController : Controller
    {      
        private ApplicationDbContext db = new ApplicationDbContext();
        // GET: Employees
        [Authorize(Roles = "example@gmail.com")]
        public ActionResult Index()
        {            
            return View(db.Employees.ToList());
            
        }

        [Authorize(Roles = "Admin")]//[Authorize(Roles = "anbu@gmail.com")]
        public ActionResult canCreateView()
        {
            //    if(ClaimsPrincipal.Current.Claims.ToList().FirstOrDefault(c => c.Type == "Surname" && c.Type == "anbu@gmail.com") != null)
            //    { 

            //    }
            //    else
            //    {

            //    }
            
            //if (((System.Security.Claims.ClaimsIdentity)User.Identity).HasClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country", "India"))
            //{
            //    List<Employee> contacts = db.Employees.ToList();
            //    return View(contacts);

            //    //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
            //}

            //else
            //    return RedirectToAction("Error"); //View();


            if (((System.Security.Claims.ClaimsIdentity)User.Identity).HasClaim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Admin"))
            {
                List<Employee> contacts = db.Employees.ToList();
                return View(contacts);

                //http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
            }

            else
                return RedirectToAction("Error"); //View();
        }

        // GET: Employees/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Employee employee = db.Employees.Find(id);
            if (employee == null)
            {
                return HttpNotFound();
            }
            return View(employee);
        }

        // GET: Employees/Create
        [Authorize(Roles = "anbu@gmail.com")]
        public ActionResult Create()
        {
            return View();
        }

        // POST: Employees/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [Authorize(Roles = "anbu@gmail.com")]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "EmployeeID,Name,Address,City,State,Zip,Email")] Employee employee)
        {
            if (ModelState.IsValid)
            {
                db.Employees.Add(employee);
                db.SaveChanges();
                return RedirectToAction("canCreateView");
            }

            return View(employee);
        }

        [Authorize(Roles = "Manager")]//[Authorize(Roles = "balaji@gmail.com")]
        public ActionResult CanEditView()
        {
            if (((System.Security.Claims.ClaimsIdentity)User.Identity).HasClaim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", "Manager")) //Admin
            {
                List<Employee> contacts = db.Employees.ToList();
                return View(contacts);
            }
            else
                return RedirectToAction("Error");        
        }



        // GET: Employees/Edit/5
        public ActionResult Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Employee employee = db.Employees.Find(id);
            if (employee == null)
            {
                return HttpNotFound();
            }
            return View(employee);
        }

        // POST: Employees/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see https://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit([Bind(Include = "EmployeeID,Name,Address,City,State,Zip,Email")] Employee employee)
        {
            if (ModelState.IsValid)
            {
                db.Entry(employee).State = EntityState.Modified;
                db.SaveChanges();
                return RedirectToAction("CanEditView");
            }
            return View(employee);
        }

        // GET: Employees/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Employee employee = db.Employees.Find(id);
            if (employee == null)
            {
                return HttpNotFound();
            }
            return View(employee);
        }

        // POST: Employees/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            Employee employee = db.Employees.Find(id);
            db.Employees.Remove(employee);
            db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            try
            {
                if (disposing)
                {
                    db.Dispose();
                }
                base.Dispose(disposing);
            }
            catch (Exception)
            {
                throw;
            }           
            
        }


        public ActionResult Error()
        {
            return View();
        }
    }
}
