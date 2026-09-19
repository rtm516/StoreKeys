namespace StoreKeys;

/// <summary>Raised when content keys cannot be obtained.</summary>
public sealed class StoreKeysException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public StoreKeysException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and an underlying cause.</summary>
    public StoreKeysException(string message, Exception inner) : base(message, inner) { }
}
