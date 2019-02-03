namespace ConsoleApp1
{
    public interface IConfigurable
    {
        /// <summary>
        /// Configures all properties and fields of the implementing class. If
        /// the implementing class is an <see cref="IEntity"/> instance, this is
        /// only necessary while the user is creating a new instance. The entities
        /// retrieved from the repository are already configured.
        /// </summary>
        void Configure();

        /// <summary>
        /// Tells if the implementing class has been configured.
        /// </summary>
        bool IsConfigured {
            get;
        }
    }
}
