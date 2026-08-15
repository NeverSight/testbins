import core.stdc.stdio : puts;

class DecodeError : Exception
{
    this(string message)
    {
        super(message);
    }
}

class SecondaryError : Exception
{
    this(string message)
    {
        super(message);
    }
}

class ConstraintDecodeError : Exception
{
    this(string message)
    {
        super(message);
    }
}

__gshared int cleanupCount;

int parseSelector(string[] arguments)
{
    if (arguments.length < 2 || arguments[1].length == 0)
        return 3;

    const digit = arguments[1][0];
    return digit >= '0' && digit <= '9' ? digit - '0' : 0;
}

int mayThrow(int selector)
{
    switch (selector)
    {
    case 0:
        throw new ConstraintDecodeError("constraint");
    case 1:
        throw new DecodeError("decode");
    case 2:
        throw new SecondaryError("secondary");
    default:
        return 40 + selector;
    }
}

int main(string[] arguments)
{
    int result;
    try
    {
        scope (exit)
            ++cleanupCount;
        result = mayThrow(parseSelector(arguments));
    }
    catch (ConstraintDecodeError)
    {
        result = 10;
    }
    catch (DecodeError)
    {
        result = 20;
    }
    catch (SecondaryError)
    {
        result = 30;
    }
    catch (Throwable)
    {
        result = 90;
    }

    if (result + cleanupCount != 44)
        return 1;
    puts("ada-d-eh probe passed");
    return 0;
}
