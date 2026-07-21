# SkillGuard — Project Rules

## Clean Code Guidelines

**Definition:** "Code is clean if it can be understood easily – by everyone on the team. Clean code can be read and enhanced by a developer other than its original author."

Source: [Clean Code Guidelines, Wojtek Łukaszuk](https://gist.github.com/wojteklu/73c6914cc446146b8b533c0988cf8d29) (summary of Robert C. Martin, *Clean Code*).

### General Principles
1. Follow standard conventions
2. Keep it simple stupid — reduce complexity wherever possible
3. Boy scout rule — leave code cleaner than you found it
4. Always investigate root causes of problems

### Design Principles
1. Keep configurable data at high levels
2. Prefer polymorphism to conditional statements
3. Separate multi-threading code
4. Prevent over-configurability
5. Use dependency injection
6. Follow Law of Demeter — classes should know only direct dependencies

### Understandability
1. Maintain consistency across similar implementations
2. Use explanatory variables
3. Encapsulate boundary conditions
4. Prefer dedicated value objects to primitives
5. Avoid logical dependencies
6. Avoid negative conditionals

### Naming Conventions
1. Choose descriptive, unambiguous names
2. Make meaningful distinctions
3. Use pronounceable names
4. Use searchable names
5. Replace magic numbers with named constants
6. Avoid type encodings and prefixes

### Function Best Practices
1. Keep functions small
2. Do one thing per function
3. Use descriptive names
4. Minimize arguments
5. Eliminate side effects
6. Avoid flag arguments — split into separate methods instead

### Comments
1. Explain yourself through code first
2. Avoid redundancy
3. Skip obvious noise
4. Don't use closing brace comments
5. Remove commented code entirely
6. Use comments to clarify intent, explain code, or warn of consequences

### Code Structure
1. Separate concepts vertically
2. Keep related code dense
3. Declare variables near their usage
4. Place dependent functions together
5. Group similar functions
6. Order functions top-to-bottom
7. Keep lines short
8. Use white space strategically

### Objects and Data Structures
1. Hide internal structure
2. Prefer data structures
3. Avoid hybrid structures
4. Keep objects small and focused
5. Maintain single responsibility
6. Limit instance variables
7. Base classes shouldn't depend on subclasses
8. Prefer many functions to behavior-selection parameters
9. Favor non-static methods

### Testing
1. One assertion per test
2. Ensure readability
3. Execute quickly
4. Maintain independence
5. Enable repeatability

### Code Smells to Avoid
1. **Rigidity** — small changes trigger cascading modifications
2. **Fragility** — breaks in multiple places from single changes
3. **Immobility** — code reuse prevented by risk or effort
4. **Needless Complexity** — over-engineering solutions
5. **Needless Repetition** — duplicated logic
6. **Opacity** — difficult-to-understand implementation
