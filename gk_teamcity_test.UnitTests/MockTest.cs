namespace Gk_teamcity_test.UnitTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
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
            var testValue = 2;
            Assert.AreEqual(testValue, 2);
        }

        /// <summary>
        /// Checks the sum2.
        /// </summary>
        [Test]
        public void CheckSum2()
        {
            var testValue = 2;
            Assert.AreNotEqual(testValue, 3);
        }
    }
}
