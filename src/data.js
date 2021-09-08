const data = {
  "Terminal Commands" : {
    "definition" : "The Terminal is a text interface for executing text-based programs, also known as the command line.",
    "types" : [
      {
        "name" : "CD",
        "symbol" : "cd <destination>",
        "definition" : "This command allows you to move around your computer's file structure. You can add ../ to move up a folder in your file structure i.e. cd ../ ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Learn/Tools_and_testing/Understanding_client-side_tools/Command_line#basic_built-in_terminal_commands"
      },
      {
        "name" : "Make Directory",
        "symbol" : "mkdir <nameOfFolder>",
        "definition" : "This command allows you to make a new folder inside your current directory.",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Learn/Tools_and_testing/Understanding_client-side_tools/Command_line#basic_built-in_terminal_commands"
      },
      {
        "name" : "Create Files",
        "symbol" : "touch <nameOfFile>",
        "definition" : "This command allows you to create a new file inside your current directory.",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Learn/Tools_and_testing/Understanding_client-side_tools/Command_line#basic_built-in_terminal_commands"
      },
      {
        "name" : "Delete",
        "symbol" : "rm <fileName>",
        "definition" : "This command allows you to remove a file or folder inside your directory.",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Learn/Tools_and_testing/Understanding_client-side_tools/Command_line#basic_built-in_terminal_commands"
      },
      {
        "name" : "List Directory",
        "symbol" : "ls",
        "definition" : "This command allows you to list the contents of the directory you're currently in. Adding -l to the command allows you to list one file or directory on each line i.e. ls -l",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Learn/Tools_and_testing/Understanding_client-side_tools/Command_line#listing_directory_contents"
      },
      {
        "name" : "Initialize a Repository",
        "symbol" : "git init",
        "definition" : "This command allows you to create an empty git repository or reinitialize an existing one.",
        "mdnLink" : "https://git-scm.com/docs/git-init"
      },
      {
        "name" : "Add File Contents",
        "symbol" : "git add",
        "definition" : "This command allows you to add file contents to the index of the repository. git add . adds all file changes to the index of the repository",
        "mdnLink" : "https://git-scm.com/docs/git-add"
      },
      {
        "name" : "Clone",
        "symbol" : "git clone",
        "definition" : "This command allows you to clone a repository into a new directory",
        "mdnLink" : "https://git-scm.com/docs/git-clone"
      },
      {
        "name" : "Commit Changes",
        "symbol" : "git commit -m 'Your message here'",
        "definition" : "This command allows you to record the changes you made to the repository with a message explaining those changes.",
        "mdnLink" : "https://git-scm.com/docs/git-commit"
      },
      {
        "name" : "Push",
        "symbol" : "git push",
        "definition" : "This command allows you to update remote refs, i.e. when working on your personal computer you can push the changes you've added and committed ",
        "mdnLink" : "https://git-scm.com/docs/git-push"
      },
      {
        "name" : "Status",
        "symbol" : "git status",
        "definition" : "This command allows you to see the working tree status.",
        "mdnLink" : "https://git-scm.com/docs/git-status"
      },
      {
        "name" : "Differences",
        "symbol" : "git diff",
        "definition" : "This command allows you to see the differences between the commits, and between the commits and the working tree.",
        "mdnLink" : "https://git-scm.com/docs/git-diff"
      },
      {
        "name" : "Pull",
        "symbol" : "git pull",
        "definition" : "This command allows you to pull changes from a remote repository into the current branch.",
        "mdnLink" : "https://git-scm.com/docs/git-pull"
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Learn/Tools_and_testing/Understanding_client-side_tools/Command_line"
  },
  "Operators" : {
    "definition" : "An operator is a symbol or set of symbols capable of manipulating a certain value.",
    "types" : [
      {
        "name" : "Assignment",
        "definition" : "This group of operators is used to assign a value to a variable",
        "types" : [
          {
            "name" : "Assignment",
            "symbol" : "=",
            "example" : "x = y",
            "meaning" : "x = y",
            "definition" : "This operator is used to assign a value to a variable",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Assignment" 
          },
          {
            "name" : "Addition Assignment",
            "symbol" : "+=",
            "example" : "x += y",
            "meaning" : "x = x + y",
            "definition" : "This operator adds the value to the right of it, to the variable to the left of it and assigns the result to the variable.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Addition_assignment" 
          },
          {
            "name" : "Subtraction Assignment",
            "symbol" : "-=",
            "example" : "x -= y",
            "meaning" : "x = x - y",
            "definition" : "This operator subtracts the value to the right of it from the variable to the left of it and assigns the result to the variable.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Subtraction_assignment" 
          },
          {
            "name" : "Multiplication Assignment",
            "symbol" : "*=",
            "example" : "x *= y",
            "meaning" : "x = x * y",
            "definition" : "This operator multiplies the variable on the left of it with the value on the right of it and assigns the result to the variable.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Multiplication_assignment" 
          },
          {
            "name" : "Division Assignment",
            "symbol" : "/=",
            "example" : "x /= y",
            "meaning" : "x = x / y",
            "definition" : "This operator divides the variable on the left of it with the value on the right of it and assigns the result to the variable.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Division_assignment" 
          },
          {
            "name" : "Remainder Assignment",
            "symbol" : "%=",
            "example" : "x %= y",
            "meaning" : "x = x % y",
            "definition" : "This operator divides the variable on the left of it by the value on the right and assigns the remainder to the variable.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Remainder_assignment" 
          },
          {
            "name" : "Exponentiation Assignment",
            "symbol" : "**=",
            "example" : "x **= y",
            "meaning" : "x = x ** y",
            "definition" : "This operator rases the value of the variable to the left of it by the value on the right of it and assigns it to the variable.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Exponentiation_assignment" 
          }
        ],
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators#assignment_operators" 
      },
      {
        "name" : "Comparison",
        "definition" : "This group of operators is used to compare values and return a logical value based on whether the comparison is true.",
        "types" : [
          {
            "name" : "Equal",
            "symbol" : "==",
            "example" : "3 == '3' returns true",
            "definition" : "This operator compares the values but not the data type and returns true if both sides of the expression are equal in value even if the data type is different.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#equality_operators" 
          },
          {
            "name" : "Not Equal",
            "symbol" : "!=",
            "example" : "3 != '4' returns true",
            "definition" : "This operator compares the values but not the data type and returns true if both sides of the expression are not equal in value even if the data type is different or the same.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#equality_operators" 
          },
          {
            "name" : "Strict Equal",
            "symbol" : "===",
            "example" : "3 === 3 returns true",
            "definition" : "This operator compares the values and data type of both sides of the expression and returns true if both sides of the expression are equal in data type and value.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#equality_operators" 
          },
          {
            "name" : "Strict Not Equal",
            "symbol" : "!==",
            "example" : "3 !== 4 returns true",
            "definition" : "This operator compares both data type and value of both sides of the expression and will return true if both sides are not equal in value or are of a different data type.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#equality_operators" 
          },
          {
            "name" : "Greater Than",
            "symbol" : ">",
            "example" : "4 > 2 returns true",
            "definition" : "This operator compares the values on the left and right of the operator and returns true if the value on the left is greater than the value on the right.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#relational_operators" 
          },
          {
            "name" : "Greater Than or Equal To",
            "symbol" : ">=",
            "example" : "4 >= 4 returns true",
            "definition" : "This operator compares the values on the left and right of the operator and returns true if the value on the left is greater than or equal to the value on the right.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#relational_operators" 
          },
          {
            "name" : "Less Than",
            "symbol" : "<",
            "example" : "5 < 9 returns true",
            "definition" : "This operator compares the values on the left and right of the operator and returns true if the value on the left is less than the value on the right.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#relational_operators" 
          },
          {
            "name" : "Less Than or Equal To",
            "symbol" : "<=",
            "example" : "5 <= 5 returns true",
            "definition" : "This operator compares the values on the left and right of the operator and returns true if the value on the left is less than or equal to the value on the right.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators#relational_operators" 
          }
        ],
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators#comparison_operators" 
      },
      {
        "name" : "Arithmetic",
        "definition" : "This group of operators is used to take numerical values and return a single numerical value.",
        "types" : [
          {
            "name" : "Remainder",
            "symbol" : "%",
            "example" : "17 % 3 returns 2",
            "definition" : "This operator divides the value on the left by the value on the right and returns the remainder.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Remainder" 
          },
          {
            "name" : "Increment",
            "symbol" : "++",
            "example" : " 3++ returns 4",
            "definition" : "This operator adds one to the value on the left of it and returns the new value.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Increment" 
          },
          {
            "name" : "Decrement",
            "symbol" : "--",
            "example" : "3-- returns 2",
            "definition" : "This operator subtracts one from the value on the left of it and returns the new value.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Decrement" 
          },
          {
            "name" : "Exponentiation",
            "symbol" : "**",
            "example" : "2 ** 3 returns 8",
            "definition" : "This operator takes the value on the left and calculates it to the power of the value on the right and returns the value.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Exponentiation" 
          }
        ],
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators#arithmetic_operators" 
      },
      {
        "name" : "Logical",
        "definition" : "This group of operators is typically used with Boolean values and when they are return a Boolean value.",
        "types" : [
          {
            "name" : "Logical AND",
            "symbol" : "&&",
            "example" : " 3 === 3 && 'the' === 'the' returns true'",
            "definition" : "This operator evaluates each expression to see if they're true. If both expressions are true it will return true, if either expression is false it will return false.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Logical_AND" 
          },
          {
            "name" : "Logical OR",
            "symbol" : "||",
            "example" : " 3 % 2 === 0 || 5 % 3 === 2 returns true",
            "definition" : "This operator evaluates each expression to see if they're true. If at least one of the expressions are true, it will return true, but if all expressions are false, it will return false.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Logical_OR" 
          },
          {
            "name" : "Logical NOT",
            "symbol" : "!",
            "example" : "!(3<2) will return true",
            "definition" : "This operator makes truthy values return false and falsy values return true. It is typically used with Boolean values.",
            "image" : " ",
            "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Logical_NOT" 
          }
        ],
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators#logical_operators" 
      }
    ],
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Expressions_and_Operators"
  },
  "Statements": {
    "definition" : "Statements consist of lines of code, single or multiple. These aren't keywords but a group of keywords.",
    "types" : [
      {
        "name" : "Return",
        "definition" : "This statement ends a function's execution and specifies a value that will be returned, if any.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/return" 
      },
      {
        "name" : "Block",
        "definition" : "This statement is used to group statements and is contained within a pair of braces ('curly brackets').",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/block" 
      },
      {
        "name" : "Break",
        "definition" : "This statement terminates the current loop, switch or label statement and transfers program control to the statement following the terminated statement.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/break" 
      },
      {
        "name" : "Continue",
        "definition" : "This statement terminates the execution of the statements in the current iteration of the current or labeled loop and continues execution of the loop with the next iteration.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/continue" 
      },
      {
        "name" : "If Statements",
        "definition" : "This statement contains a conditional statement that if found to be truthy will execute a code block. If the conditional statement is found to be falsy it will skip the code block and move to the next.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/if...else" 
      },
      {
        "name" : "Conditional (ternary)",
        "definition" : "This is similar to an If ... Else statement in that it evaluates a condition which is followed by a question mark, then if the condition is true it executes the first statement, if it is falsy it executes the second statement. The statements are separated by a colon : i.e. condition ? truthy : falsy ",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Conditional_Operator" 
      },
      {
        "name" : "Switch",
        "definition" : "This statement evaluates an expression, then matches the expression's value to a case value to execute the case's code block. When the value of the expression does not match any of the case's then it will default to the default code block.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/switch" 
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements" 
  },
  "Variables" : {
    "definition" : "Variables are named containers that store data we can use later in functions and logic.",
    "types" : [
      {
        "name" : "Let",
        "example" : "let var1 = 8;",
        "definition" : "This statement declares a local variable within the current code block, optionally initializing it to a variable.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/let" 
      },
      {
        "name" : "Const",
        "example" : "const array = [1, 2, 3, 4]",
        "definition" : "This statement declares a variable scoped within the current code block but unlike let, once a const is declared it's value cannot be changed.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/const" 
      },
      {
        "name" : "Var",
        "example" : "var string = 'Hello World'",
        "definition" : "This statement declares a function-scoped or globally-scoped variable, with the option to initialize the value when it is declared.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/var" 
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements#declarations" 
  },
  "Data Types" : {
    "definition" : "Data types are the structures in place within JavaScript that allow us to store data. Data types differ in each programming language so it is important to understand what data types you can work with.",
    "types" : [
      {
        "name" : "Strings",
        "example" : " 'Hello World' or \"Hello World\" ",
        "definition" : "This data type is used to store textual data. The length of a string is determined by the number of elements in it. The first element is at an index 0, and the last element's index will always be one less than the length.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#string_type" 
      },
      {
        "name" : "Numbers",
        "example" : "1 or 1.1 or -1",
        "definition" : "This data type is used to store numerical values such as a number i.e. 1 or -1, or a decimal i.e. 1.1.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#number_type" 
      },
      {
        "name" : "Boolean",
        "example" : "true or false",
        "definition" : "This data type that can only have the values true or false. These data types are often used to decide what sections of code to run such as if ... else statements or repeat such as loops.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Glossary/Boolean" 
      },
      {
        "name" : "Undefined",
        "example" : "undefined",
        "definition" : "This data type is specific to variables that have not been assigned a value yet, hence undefined because they are not defined.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#undefined_type" 
      },
      {
        "name" : "Null",
        "example" : "null",
        "definition" : "This data type is a value that represents a reference that points to a nonexisent or invalid object or address.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Glossary/Null" 
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures" 
  },
  "Control Flow" : {
    "definition" : "Control Flow refers to the order in which a computer executes statements in a script. Usually code is run top to bottom, left to right, but statements and structures can alter the flow.",
    "types" : [
      {
        "name" : "Truthiness",
        "definition" : "A truthy value is a value that is considered true when encountered in a boolean context. All values are truthy unless they are defined as falsy.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Glossary/Truthy" 
      },
      {
        "name" : "Falsiness",
        "definition" : "A falsy value is a value that is considered false when encountered in a boolean context. In Example: the number 0 is a falsy value for a number data type, or an empty string \"\", '', ``, is a falsy value for a string.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Glossary/Falsy" 
      },
      {
        "name" : "Scope",
        "definition" : "Scope is the context in which values and expressions can be used or referenced. If a variable is not in the current scope then it is unavailable or undefined for use.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Glossary/Scope" 
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Glossary/Control_flow" 
  },
  "Loops" : {
    "definition" : "Loops are used to repeat certain blocks of code a specific number of times.",
    "types" : [
      {
        "name" : "While",
        "example" : " while (condition) {code if true} ",
        "definition" : "This loop executes the code block as long as the condition is true.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/while" 
      },
      {
        "name" : "Do ... While",
        "example" : " do { code if true } while (condition) ",
        "definition" : "This loop executes the code block until the condition evaluates to false",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/do...while" 
      },
      {
        "name" : "For",
        "example" : "for (initialize; condition; loop) { code if true } ",
        "definition" : "This loop has three optional expressions instead of one condition, but will still execute the following blocks of code as longs as those conditions are met.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for" 
      },
      {
        "name" : "For ... in",
        "example" : "for (const variable in object) { code for each property of the object }",
        "definition" : "This loop goes over each property of an object that are keyed by strings.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for...in" 
      },
      {
        "name" : "For ... of",
        "example" : "for (const variable of object) { code for each element of the object }",
        "definition" : "This loop is used to loop over objects, like arrays, and do something with each value in the array.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/for...of" 
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Loops_and_iteration" 
  },
  "Functions" : {
    "definition" : "Each function is actually an object, however functions run specific blocks of code when called inside our logic or in response to an users interaction with our logic. Functions have a global scope. Each function is an action and should be named containing verbs describing what the function does in camelCase i.e. a function that adds two variables should be named add, or a function that happens on click should be handleClick.",
    "example" : " function [name] (parameters) { statements }",
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function" 
  },
  "Math" : {
    "definition" : "Math is a built in object similar to functions but not the same, that has properties and methods for mathematical functionality which can be called within functions and logic.",
    "types": [
      {
        "name" : "Math.round()",
        "example" : " Math.round(5.8) returns 6 and Math.round(5.25) returns 5 ",
        "definition" : "This Math function returns the value of a number rounded to the nearest whole number.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/round" 
      },
      {
        "name" : "Math.floor()",
        "example" : " Math.floor(2.95) returns 2 and Math.floor(7) returns 7 ",
        "definition" : "This Math function returns the largest whole number less than or equal to the given number.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/floor" 
      },
      {
        "name" : "Math.ceil()",
        "example" : " Math.ceil(9.1) returns 10 and Math.ceil(6) returns 6 ",
        "definition" : "This Math function always rounds a number up to the nearest whole number of a given number.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/ceil" 
      },
      {
        "name" : "Math.random()",
        "example" : " Math.floor( Math.random() * 4 ) will return anything from 0 - 3 (remember that Math.Floor always rounds down) ",
        "definition" : "This Math function returns a random number between 0 and 1, never quite 0 and never quite 1. You can then scale this number, by multiplying the result by the desired absolute maximum, to get a desired range of possibilities.",
        "image" : " ",
        "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random" 
      }
    ],
    "image" : " ",
    "mdnLink" : "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math"
  }
}

export default data;