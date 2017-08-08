namespace Gk_teamcity_test.UnitTests
{
    using NUnit.Framework;

    /// <summary>
    /// Mock Test
    /// </summary>
    [TestFixture]
    public class MockTest
    {
        /// <summary>
        /// Checks the sum.
        /// </summary>
        [Test]
        public void CheckSum()
        {
            //dsfdsfsdf
            var testValue = 2;
            //ddsfsdf
            Assert.AreEqual(testValue, 2);
        }

        /// <summary>
        /// Checks the sum2.
        /// </summary>
        [Test]
        public void CheckSum2()
        {
            //fdsfdfsd
            var testValue = 2;
            Assert.AreNotEqual(testValue, 3);
        }
    }
}
