| Element                                    | Style                 | Example                                      |
| ------------------------------------------ | --------------------- | -------------------------------------------- |
| **Classes / Structs / Enums / Typedefs**   | `PascalCase`          | `class PlayerCharacter {}`                   |
| **Functions / Methods (public + private)** | `snake_case`          | `void take_damage();`                        |
| **Variables (local + parameters)**         | `snake_case`          | `int total_score;`                           |
| **Member Variables (private)**             | `snake_case_`         | `int health_points_;`                        |
| **Constants**                              | `ALL_CAPS_SNAKE_CASE` | `const int MAX_HEALTH = 100;`                |
| **Namespaces**                             | `snake_case`          | `namespace game_logic { ... }`               |
| **Macros**                                 | `ALL_CAPS_SNAKE_CASE` | `#define ENABLE_LOGGING`                     |
| **Files**                                  | `snake_case`          | `player_character.h`, `player_character.cpp` |

```
class PlayerCharacter {
public:
    // Public constants
    static constexpr int MAX_HEALTH = 100;

    // Constructors / destructors
    PlayerCharacter();
    ~PlayerCharacter();

    // Public interface
    void take_damage(int amount);
    void heal(int amount);

protected:
    // Protected hooks
    virtual void on_damage_taken();

private:
    // Private helpers
    void apply_damage(int amount);
    int calculate_effective_armor() const;

    // Private data members (always last)
    int health_points_;
    int armor_points_;
    bool is_alive_;
};
```