using Microsoft.EntityFrameworkCore;
using AuthenticationSystemAPI.Models;

/*
 * ===================================================================
 * DATABASE CONTEXT - Bridge between C# objects and SQL Server
 * ===================================================================
 * 
 * Clean Architecture - This is the "Infrastructure" or "Data" layer:
 * - Implements data access logic
 * - Depends on Domain layer (Models)
 * - No business logic here - just data operations
 * 
 * Entity Framework Core (EF Core):
 * - Object-Relational Mapper (ORM)
 * - Translates C# code to SQL queries
 * - Code First: We define classes, EF generates database schema
 * 
 * Key Methods:
 * - OnModelCreating: Define table structure, indexes, constraints
 * - SaveChanges: Persist changes to database
 */
namespace AuthenticationSystemAPI.Data;

public class AppDbContext : DbContext
{
    /*
     * Constructor with Dependency Injection
     * --------------------------------------
     * ASP.NET Core will automatically inject DbContextOptions
     * when we register it in Program.cs
     * 
     * This allows us to:
     * - Use different databases for different environments
     * - Easy testing with in-memory database
     * - Connection string management via configuration
     */
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
        // Base(options) passes configuration to parent DbContext
    }

    /*
     * DbSet<User> - Represents the Users table
     * ----------------------------------------
     * 
     * Think of it as:
     * - DbSet = Table
     * - User = Row
     * - Properties = Columns
     * 
     * LINQ Operations (converted to SQL):
     * - .Where(x => x.Name == "value") → WHERE Name = 'value'
     * - .FirstOrDefault(x => x.Id == 1) → SELECT TOP 1 * FROM Users WHERE Id = 1
     * - .Add(user) → INSERT INTO Users ...
     * - .Remove(user) → DELETE FROM Users ...
     */
    public DbSet<User> Users { get; set; }

    /*
     * OnModelCreating - Define database schema
     * ----------------------------------------
     * Called by EF Core when building the model
     * Here we configure:
     * - Primary keys
     * - Indexes (for faster queries)
     * - Column constraints
     * - Relationships between tables
     */
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure User entity
        modelBuilder.Entity<User>(entity =>
        {
            // PRIMARY KEY: Id is the primary key
            entity.HasKey(u => u.Id);

            // UNIQUE INDEX on Username: No two users can have same username
            // This creates a unique constraint in SQL Server
            entity.HasIndex(u => u.Username).IsUnique();

            // UNIQUE INDEX on Email: No two users can have same email
            entity.HasIndex(u => u.Email).IsUnique();

            // COLUMN CONFIGURATION
            // Username: Required, max 100 chars
            entity.Property(u => u.Username)
                .IsRequired()
                .HasMaxLength(100);

            // Email: Required, max 255 chars
            entity.Property(u => u.Email)
                .IsRequired()
                .HasMaxLength(255);

            // PasswordHash: Required (we always hash passwords)
            entity.Property(u => u.PasswordHash)
                .IsRequired();

            // Role: Optional, defaults to "User" in SQL
            entity.Property(u => u.Role)
                .HasMaxLength(50)
                .HasDefaultValue("User");

            // CreatedAt: Store as UTC, not local time
            entity.Property(u => u.CreatedAt)
                .HasDefaultValueSql("GETUTCDATE()");
        });

        // SEED DATA (Optional - for development/testing)
        // Uncomment to create an initial admin user
        /*
        modelBuilder.Entity<User>().HasData(
            new User
            {
                Id = 1,
                Username = "admin",
                Email = "admin@example.com",
                // Password: "Admin123!" (hashed with BCrypt)
                PasswordHash = "$2a$11$...", 
                Role = "Admin",
                CreatedAt = DateTime.UtcNow
            }
        );
        */
    }
}

