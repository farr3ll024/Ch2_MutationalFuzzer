using System;
using NUnit.Framework;

namespace Ch2_MutationalFuzzerTests
{
    [TestFixture]
    public class Tests
    {
        [Test]
        public void FuzzerPass()
        {
            Assert.True(true);
        }

        [Test]
        public void FuzzerFail()
        {
            Assert.True(true);
        }
    }
}