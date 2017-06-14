using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;

namespace gk_teamcity_test.UnitTests
{
    [TestFixture]
    public class MockTest
    {
        [Test]
        public void CheckSum()
        {
            var testValue = 2;
            Assert.AreEqual(testValue, 2);
        }

        [Test]
        public void CheckSum2()
        {
            var testValue = 2;
            Assert.AreNotEqual(testValue, 3);
        }
    }
}
